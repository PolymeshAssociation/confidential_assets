use crate::{
    elgamal::{
        multi_key::{CipherTextMultiKey, CipherTextMultiKeyBuilder},
        CipherText, CipherTextHint, CommitmentWitness,
        ElgamalPublicKey,
    },
    errors::{Error, Result},
    proofs::{
        bulletproofs::PedersenGens,
        ciphertext_refreshment_proof::{
            CipherTextRefreshmentProverAwaitingChallenge, CipherTextRefreshmentVerifier,
            CipherEqualSamePubKeyProof,
        },
        ciphertext_same_value_proof::{
            CipherTextSameValueProof,
            CipherTextSameValueProverAwaitingChallenge, CipherTextSameValueVerifier,
        },
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        range_proof::InRangeProof,
    },
    ElgamalKeys,
    Balance,
    Scalar,
    BALANCE_RANGE,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use rand_core::{CryptoRng, RngCore};

use codec::{Decode, Encode};
use sp_std::{
  collections::btree_map::BTreeMap,
};

pub const MAX_AUDITORS: usize = 10;

// -------------------------------------------------------------------------------------
// -                       Confidential Transfer Transaction                           -
// -------------------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditorId(#[codec(compact)] pub u32);

#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditorPayload {
    pub encrypted_hint: CipherTextHint,
    pub amount_idx: u8,
}

/// Holds the proofs and memo of the confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConfidentialTransferProof {
    pub amounts: CipherTextMultiKey,
    pub amount_equal_cipher_proof: CipherTextSameValueProof,
    pub non_neg_amount_proof: InRangeProof,
    pub enough_fund_proof: InRangeProof,
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub auditors: BTreeMap<AuditorId, AuditorPayload>,
    pub refreshed_enc_balance: CipherText,
}

impl ConfidentialTransferProof {
    pub fn keys(
        sender_key: &ElgamalPublicKey,
        receiver_key: &ElgamalPublicKey,
        auditors_enc_pub_keys: &BTreeMap<AuditorId, ElgamalPublicKey>,
    ) -> Result<Vec<ElgamalPublicKey>> {
        ensure!(auditors_enc_pub_keys.len() <= MAX_AUDITORS, Error::TooManyAuditors);
        // All public keys.
        let mut keys = Vec::with_capacity(auditors_enc_pub_keys.len() + 2);
        keys.push(*sender_key);
        keys.push(*receiver_key);
        for auditor in auditors_enc_pub_keys {
            keys.push(*auditor.1);
        }

        Ok(keys)
    }

    /// Create a confidential asset transfer proof.
    pub fn new<T: RngCore + CryptoRng>(
        sender_account: &ElgamalKeys,
        sender_init_balance: &CipherText,
        sender_balance: Balance,
        receiver_pub_key: &ElgamalPublicKey,
        auditors_enc_pub_keys: &BTreeMap<AuditorId, ElgamalPublicKey>,
        amount: Balance,
        rng: &mut T,
    ) -> Result<Self> {
        // Ensure the sender has enough funds.
        ensure!(
            sender_balance >= amount,
            Error::NotEnoughFund {
                balance: sender_balance,
                transaction_amount: amount
            }
        );
        // Verify the sender's balance.
        sender_account
            .verify(sender_init_balance, &sender_balance.into())?;

        // All public keys.
        let keys = Self::keys(&sender_account.public, receiver_pub_key, auditors_enc_pub_keys)?;

        // CommitmentWitness for transaction amount.
        let witness = CommitmentWitness::new(amount.into(), Scalar::random(rng));
        let amounts = CipherTextMultiKeyBuilder::new(&witness, keys.iter());
        let amount_enc_blinding = witness.blinding();

        // Prove that the amount is not negative.
        let non_neg_amount_proof =
            InRangeProof::prove(amount.into(), amount_enc_blinding, BALANCE_RANGE, rng)?;

        // Prove that the amount encrypted under different public keys are the same.
        let gens = PedersenGens::default();
        let amount_equal_cipher_proof = single_property_prover(
            CipherTextSameValueProverAwaitingChallenge {
                keys,
                w: witness.clone(),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Refresh the encrypted balance and prove that the refreshment was done
        // correctly.
        let balance_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_balance = sender_init_balance.refresh_with_hint(
            &sender_account.secret,
            balance_refresh_enc_blinding,
            &sender_balance.into(),
        )?;

        let balance_refreshed_same_proof = single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                sender_account.secret.clone(),
                *sender_init_balance,
                refreshed_enc_balance,
                &gens,
            ),
            rng,
        )?;

        // Prove that the sender has enough funds.
        let blinding = balance_refresh_enc_blinding - amount_enc_blinding;
        let enough_fund_proof = InRangeProof::prove(
            (sender_balance - amount).into(),
            blinding,
            BALANCE_RANGE,
            rng,
        )?;

        // Add the necessary payload for auditors.
        let auditors = auditors_enc_pub_keys
            .iter()
            .enumerate()
            .map(|(idx, (auditor_id, _auditor_enc_pub_key))| {
                (*auditor_id, AuditorPayload {
                    amount_idx: (idx + 2) as u8,
                    encrypted_hint: CipherTextHint::new(&witness, rng),
                })
            })
            .collect();

        Ok(Self {
            amounts: amounts.build(),
            amount_equal_cipher_proof,
            non_neg_amount_proof,
            enough_fund_proof,
            balance_refreshed_same_proof,
            refreshed_enc_balance,
            auditors,
        })
    }

    /// Verify the ZK-proofs using only public information.
    pub fn verify<R: RngCore + CryptoRng>(
        &self,
        sender_account: &ElgamalPublicKey,
        sender_init_balance: &CipherText,
        receiver_account: &ElgamalPublicKey,
        auditors_enc_pub_keys: &BTreeMap<AuditorId, ElgamalPublicKey>,
        rng: &mut R,
    ) -> Result<()> {
        let gens = &PedersenGens::default();

        // Verify that all auditors' payload is included, and
        // that the auditors' ciphertexts encrypt the same amount as sender's ciphertext.
        ensure!(
            self.auditors.len() == auditors_enc_pub_keys.len(),
            Error::AuditorPayloadError
        );

        // Verify that the encrypted amounts are equal.
        let keys = Self::keys(sender_account, receiver_account, auditors_enc_pub_keys)?;
        single_property_verifier(
            &CipherTextSameValueVerifier {
                keys,
                ciphertexts: self.amounts.ciphertexts(),
                pc_gens: &gens,
            },
            &self.amount_equal_cipher_proof,
        )?;

        // Verify that the amount is not negative.
        let commitment = self.sender_amount().y.compress();
        self.non_neg_amount_proof.verify(&commitment, BALANCE_RANGE, rng)?;

        // verify that the balance refreshment was done correctly.
        single_property_verifier(
            &CipherTextRefreshmentVerifier::new(
                *sender_account,
                *sender_init_balance,
                self.refreshed_enc_balance,
                &gens,
            ),
            &self.balance_refreshed_same_proof,
        )?;

        // Verify that the balance has enough fund.
        let updated_balance = self.refreshed_enc_balance - self.sender_amount();
        let commitment = updated_balance.y.compress();
        self.enough_fund_proof.verify(&commitment, BALANCE_RANGE, rng)?;

        Ok(())
    }

    /// Receiver verify the transaction amount using their private key.
    pub fn receiver_verify(
        &self,
        receiver_account: ElgamalKeys,
        amount: Balance,
    ) -> Result<()> {
        // Check that the amount is correct.
        receiver_account
            .verify(&self.receiver_amount(), &amount.into())
            .map_err(|_| Error::TransactionAmountMismatch {
                expected_amount: amount,
            })?;

        Ok(())
    }

    /// Verify the initialized transaction.
    /// Audit the sender's encrypted amount.
    pub fn auditor_verify(
        &self,
        auditor_id: AuditorId,
        auditor_enc_key: &ElgamalKeys,
    ) -> Result<Balance> {
        match self.auditors.get(&auditor_id) {
            Some(auditor) => {
                let enc_amount = auditor.encrypted_hint.
                    ciphertext_with_hint(self.amount(auditor.amount_idx.into()));
                auditor_enc_key
                    .const_time_decrypt(&enc_amount)
            }
            None => {
                Err(Error::AuditorPayloadError)
            }
        }
    }

    pub fn amount(&self, idx: usize) -> CipherText {
        self.amounts.get(idx).unwrap_or_default()
    }

    pub fn sender_amount(&self) -> CipherText {
        self.amount(0)
    }

    pub fn receiver_amount(&self) -> CipherText {
        self.amount(1)
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{
        elgamal::ElgamalSecretKey,
        ElgamalKeys, ElgamalPublicKey, CipherText, Scalar,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rand_core::{CryptoRng, RngCore};
    use wasm_bindgen_test::*;

    // -------------------------- mock helper methods -----------------------

    fn mock_gen_enc_key_pair(seed: u8) -> ElgamalKeys {
        let mut rng = StdRng::from_seed([seed; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        ElgamalKeys {
            public: elg_pub,
            secret: elg_secret,
        }
    }

    fn mock_gen_account<R: RngCore + CryptoRng>(
        receiver_enc_pub_key: ElgamalPublicKey,
        balance: Balance,
        rng: &mut R,
    ) -> Result<CipherText> {
        let (_, enc_balance) = receiver_enc_pub_key.encrypt_value(Scalar::from(balance), rng);

        Ok(enc_balance)
    }

    // -------------------------- tests -----------------------

    // ------------------------------ Test simple scenarios

    #[test]
    #[wasm_bindgen_test]
    fn test_ctx_create_finalize_validate_success() {
        let sender_balance = 40;
        let receiver_balance = 0;
        let amount = 30;

        let mut rng = StdRng::from_seed([17u8; 32]);

        let sender_account = mock_gen_enc_key_pair(10u8);

        let receiver_account = mock_gen_enc_key_pair(12u8);

        let mediator_account = mock_gen_enc_key_pair(14u8);

        let receiver_init_balance =
            mock_gen_account(receiver_account.public, receiver_balance, &mut rng).unwrap();

        let sender_init_balance =
            mock_gen_account(sender_account.public, sender_balance, &mut rng).unwrap();

        let auditor_keys = BTreeMap::from([(AuditorId(0), mediator_account.public)]);
        // Create the transaction and check its result and state
        let result = ConfidentialTransferProof::new(
            &sender_account,
            &sender_init_balance,
            sender_balance,
            &receiver_account.public,
            &auditor_keys,
            amount,
            &mut rng,
        );
        let ctx_init_data = result.unwrap();

        // Finalize the transaction and check its state.
        ctx_init_data.receiver_verify(receiver_account.clone(), amount)
            .unwrap();

        // Justify the transaction
        let _result = ctx_init_data
            .auditor_verify(AuditorId(0), &mediator_account)
            .unwrap();

        assert!(ctx_init_data.verify(
                &sender_account.public,
                &sender_init_balance,
                &receiver_account.public,
                &auditor_keys,
                &mut rng,
            )
            .is_ok());

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        let updated_sender_balance =
            sender_init_balance - ctx_init_data.sender_amount();
        let updated_receiver_balance =
            receiver_init_balance + ctx_init_data.receiver_amount();

        assert!(sender_account
            .verify(&updated_sender_balance, &(sender_balance - amount).into())
            .is_ok());
        assert!(receiver_account
            .verify(
                &updated_receiver_balance,
                &(receiver_balance + amount).into()
            )
            .is_ok());
    }

    // ------------------------------ Test Auditing Logic
    fn account_create_helper(
        seed0: [u8; 32],
        seed1: u8,
        balance: Balance,
    ) -> (ElgamalKeys, CipherText) {
        let mut rng = StdRng::from_seed(seed0);

        let enc_keys = mock_gen_enc_key_pair(seed1);

        let init_balance = mock_gen_account(enc_keys.public, balance, &mut rng).unwrap();

        (enc_keys, init_balance)
    }

    fn test_transaction_auditor_helper(
        sender_auditor_list: &[(AuditorId, ElgamalPublicKey)],
        mediator_auditor_list: &[(AuditorId, ElgamalPublicKey)],
        mediator_check_fails: bool,
        validator_auditor_list: &[(AuditorId, ElgamalPublicKey)],
        validator_check_fails: bool,
        auditors_list: &[(AuditorId, ElgamalKeys)],
    ) {
        let mut sender_auditor_list = BTreeMap::from_iter(sender_auditor_list.iter().copied());
        let mut mediator_auditor_list = BTreeMap::from_iter(mediator_auditor_list.iter().copied());
        let mut validator_auditor_list = BTreeMap::from_iter(validator_auditor_list.iter().copied());
        let sender_balance = 500;
        let receiver_balance = 0;
        let amount = 400;

        let mut rng = StdRng::from_seed([19u8; 32]);

        let mediator_enc_keys = mock_gen_enc_key_pair(140u8);
        let mediator_id = AuditorId(140);
        sender_auditor_list.insert(mediator_id, mediator_enc_keys.public);
        mediator_auditor_list.insert(mediator_id, mediator_enc_keys.public);
        validator_auditor_list.insert(mediator_id, mediator_enc_keys.public);

        let (receiver_account, receiver_init_balance) =
            account_create_helper([18u8; 32], 120u8, receiver_balance);

        let (sender_account, sender_init_balance) =
            account_create_helper([17u8; 32], 100u8, sender_balance);

        // Create the transaction and check its result and state
        let ctx_init = ConfidentialTransferProof::new(
                &sender_account,
                &sender_init_balance,
                sender_balance,
                &receiver_account.public,
                &sender_auditor_list,
                amount,
                &mut rng,
            )
            .unwrap();

        // Finalize the transaction and check its state
        ctx_init.receiver_verify(receiver_account.clone(), amount)
            .unwrap();

        // Justify the transaction
        ctx_init.auditor_verify(
            mediator_id,
            &mediator_enc_keys
        ).unwrap();

        if mediator_check_fails {
            let result = ctx_init.verify(
                &sender_account.public,
                &sender_init_balance,
                &receiver_account.public,
                &mediator_auditor_list,
                &mut rng,
            );
            assert_err!(result, Error::AuditorPayloadError);
            return;
        }

        let result = ctx_init.verify(
            &sender_account.public,
            &sender_init_balance,
            &receiver_account.public,
            &validator_auditor_list,
            &mut rng,
        );

        if validator_check_fails {
            assert_err!(result, Error::AuditorPayloadError);
            return;
        }

        assert!(result.is_ok());

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        let updated_sender_balance = sender_init_balance - ctx_init.sender_amount();
        let updated_receiver_balance =
            receiver_init_balance + ctx_init.receiver_amount();

        assert!(sender_account
            .verify(&updated_sender_balance, &(sender_balance - amount).into())
            .is_ok());
        assert!(receiver_account
            .verify(
                &updated_receiver_balance,
                &(receiver_balance + amount).into()
            )
            .is_ok());

        // ----------------------- Auditing
        for auditor in auditors_list {
            assert!(ctx_init
                .auditor_verify(
                    auditor.0,
                    &auditor.1,
                )
                .is_ok());
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_transaction_auditor() {
        // Make imaginary auditors.
        let auditors_num = 5;
        let auditors_secret_vec: Vec<(AuditorId, ElgamalKeys)> = (0..auditors_num)
            .map(|index| {
                let auditor_keys = mock_gen_enc_key_pair(index as u8);
                (AuditorId(index), auditor_keys)
            })
            .collect();
        let auditors_secret_list = auditors_secret_vec.as_slice();

        let auditors_vec: Vec<(AuditorId, ElgamalPublicKey)> = auditors_secret_vec
            .iter()
            .map(|a| (a.0, a.1.public))
            .collect();

        let auditors_list = auditors_vec.as_slice();

        // Positive tests.

        // Include `auditors_num` auditors.
        test_transaction_auditor_helper(
            auditors_list,
            auditors_list,
            false,
            auditors_list,
            false,
            auditors_secret_list,
        );

        // Change the order of auditors lists on the mediator and validator sides.
        // The tests still must pass.
        let mediator_auditor_list = vec![
            auditors_vec[1],
            auditors_vec[0],
            auditors_vec[3],
            auditors_vec[2],
            auditors_vec[4],
        ];
        let validator_auditor_list = vec![
            auditors_vec[4],
            auditors_vec[3],
            auditors_vec[2],
            auditors_vec[1],
            auditors_vec[0],
        ];

        let mediator_auditor_list = mediator_auditor_list;
        let validator_auditor_list = validator_auditor_list;

        test_transaction_auditor_helper(
            auditors_list,
            &mediator_auditor_list,
            false,
            &validator_auditor_list,
            false,
            auditors_secret_list,
        );

        // Asset doesn't have any auditors.
        test_transaction_auditor_helper(&[], &[], false, &[], false, &[]);

        // Negative tests.

        // Sender misses an auditor. Mediator catches it.
        let four_auditor_list = vec![
            auditors_vec[1],
            auditors_vec[0],
            auditors_vec[3],
            auditors_vec[2],
        ];
        let four_auditor_list = four_auditor_list.as_slice();

        test_transaction_auditor_helper(
            four_auditor_list,
            &mediator_auditor_list,
            true,
            &validator_auditor_list,
            true,
            auditors_secret_list,
        );

        // Sender and mediator miss an auditor, but validator catches them.
        test_transaction_auditor_helper(
            four_auditor_list,
            four_auditor_list,
            false,
            &validator_auditor_list,
            true,
            auditors_secret_list,
        );

        // Sender doesn't include any auditors. Mediator catches it.
        test_transaction_auditor_helper(
            &[],
            &mediator_auditor_list,
            true,
            &validator_auditor_list,
            true,
            auditors_secret_list,
        );

        // Sender and mediator don't believe in auditors but validator does.
        test_transaction_auditor_helper(
            &[],
            &[],
            false,
            &validator_auditor_list,
            true,
            auditors_secret_list,
        );
    }
}
