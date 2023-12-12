use crate::{
    elgamal::{
        multi_key::{CipherTextMultiKey, CipherTextMultiKeyBuilder},
        CipherText, CommitmentWitness, ElgamalPublicKey,
    },
    errors::{Error, Result},
    proofs::{
        bulletproofs::PedersenGens,
        ciphertext_refreshment_proof::{
            CipherEqualSamePubKeyProof, CipherTextRefreshmentProverAwaitingChallenge,
            CipherTextRefreshmentVerifier,
        },
        ciphertext_same_value_proof::{
            CipherTextSameValueProof, CipherTextSameValueProverAwaitingChallenge,
            CipherTextSameValueVerifier,
        },
        encryption_proofs::single_property_prover_with_transcript,
        encryption_proofs::single_property_verifier_with_transcript,
        range_proof::InRangeProof,
    },
    AssetId, Balance, ElgamalKeys, Scalar, BALANCE_RANGE,
};

use rand_core::{CryptoRng, RngCore};

#[cfg(not(feature = "std"))]
use alloc::{self as std, vec::Vec};
use codec::{Decode, Encode};
use merlin::Transcript;
use std::collections::btree_map::BTreeMap;
use std::collections::btree_set::BTreeSet;

pub const MAX_AUDITORS: u32 = 8;
pub const MAX_TOTAL_SUPPLY: u64 = 1_000_000_000_000u64;

/// The domain label for the Confidential Transfer proofs.
pub const CONFIDENTIAL_TRANSFER_PROOF_LABEL: &[u8] = b"PolymeshConfidentialTransferProof";

/// Public input parameters needed to verify confidential transfer proof.
#[derive(Clone, Encode, Decode, Debug)]
pub struct AssetTransfer {
    pub sender_enc_balance: CipherText,
    pub auditors_keys: BTreeSet<ElgamalPublicKey>,
}

/// Input parameters (including unencrypted values) needed to generate confidential transfer proof.
#[derive(Clone, Encode, Decode, Debug)]
pub struct AssetTransferWithSecret {
    pub sender_enc_balance: CipherText,
    pub auditors_keys: BTreeSet<ElgamalPublicKey>,
    pub sender_balance: Balance,
    pub amount: Balance,
}

impl AssetTransferWithSecret {
    /// Create a confidential asset transfer proof.
    pub fn into_proof<T: RngCore + CryptoRng>(
        self,
        sender: &ElgamalKeys,
        receiver: &ElgamalPublicKey,
        rng: &mut T,
    ) -> Result<ConfidentialTransferProof> {
        Ok(ConfidentialTransferProof::new(
            sender,
            &self.sender_enc_balance,
            self.sender_balance,
            receiver,
            &self.auditors_keys,
            self.amount,
            rng,
        )?)
    }
}

/// A set of confidential asset transfers between the same sender & receiver.
#[derive(Clone, Encode, Decode, Debug)]
pub struct ConfidentialTransfers {
    pub proofs: BTreeMap<AssetId, ConfidentialTransferProof>,
}

impl ConfidentialTransfers {
    /// Create a set of confidential asset transfer proofs.
    pub fn new<T: RngCore + CryptoRng>(
        sender: &ElgamalKeys,
        receiver: &ElgamalPublicKey,
        transfers: BTreeMap<AssetId, AssetTransferWithSecret>,
        rng: &mut T,
    ) -> Result<Self> {
        Ok(Self {
            proofs: transfers
                .into_iter()
                .map(|(asset, transfer)| {
                    transfer
                        .into_proof(sender, receiver, rng)
                        .map(|p| (asset, p))
                })
                .collect::<Result<_>>()?,
        })
    }

    /// Verify the ZK-proofs using only public information.
    pub fn verify<R: RngCore + CryptoRng>(
        &self,
        sender: &ElgamalPublicKey,
        receiver: &ElgamalPublicKey,
        transfers: BTreeMap<AssetId, AssetTransfer>,
        rng: &mut R,
    ) -> Result<()> {
        // Ensure the number of assets is the same.
        ensure!(
            self.proofs.len() == transfers.len(),
            Error::VerificationError
        );
        for (asset, proof) in &self.proofs {
            match transfers.get(asset) {
                Some(transfer) => {
                    proof.verify(
                        sender,
                        &transfer.sender_enc_balance,
                        receiver,
                        &transfer.auditors_keys,
                        rng,
                    )?;
                }
                None => {
                    log::warn!("Missing asset {asset:?}.");
                    return Err(Error::VerificationError);
                }
            }
        }
        Ok(())
    }
}

// -------------------------------------------------------------------------------------
// -                       Confidential Transfer Transaction                           -
// -------------------------------------------------------------------------------------

/// The confidential transfer proof created by the sender.
#[derive(Clone, Encode, Decode, Debug)]
pub struct ConfidentialTransferProof {
    // Transaction amount encrypted with all public keys (sender, receiver and auditor keys).
    pub(crate) amounts: CipherTextMultiKey,
    // SCALE encoded inner proof.
    pub(crate) encoded_inner_proof: Vec<u8>,
}

impl ConfidentialTransferProof {
    /// Create a confidential asset transfer proof.
    pub fn new<T: RngCore + CryptoRng>(
        sender_account: &ElgamalKeys,
        sender_init_balance: &CipherText,
        sender_balance: Balance,
        receiver_key: &ElgamalPublicKey,
        auditors_keys: &BTreeSet<ElgamalPublicKey>,
        amount: Balance,
        rng: &mut T,
    ) -> Result<Self> {
        let mut transcript = Transcript::new(CONFIDENTIAL_TRANSFER_PROOF_LABEL);
        // Ensure the sender has enough funds.
        ensure!(
            sender_balance >= amount,
            Error::NotEnoughFund {
                balance: sender_balance,
                transaction_amount: amount
            }
        );
        // Verify the sender's balance.
        sender_account.verify(sender_init_balance, &sender_balance.into())?;

        // All public keys.
        let keys = Self::keys(&sender_account.public, receiver_key, auditors_keys)?;

        // CommitmentWitness for transaction amount.
        let witness = CommitmentWitness::new(amount.into(), Scalar::random(rng));
        let amounts = CipherTextMultiKeyBuilder::new(&witness, keys.iter()).build();
        let amount_enc_blinding = witness.blinding();

        // Prove that the amount encrypted under different public keys are the same.
        let gens = PedersenGens::default();
        let amount_equal_cipher_proof = single_property_prover_with_transcript(
            &mut transcript,
            CipherTextSameValueProverAwaitingChallenge::new(
                keys,
                amounts.ciphertexts(),
                witness.clone(),
                &gens,
            ),
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

        let balance_refreshed_same_proof = single_property_prover_with_transcript(
            &mut transcript,
            CipherTextRefreshmentProverAwaitingChallenge::new(
                sender_account.secret.clone(),
                sender_account.public.clone(),
                *sender_init_balance,
                refreshed_enc_balance,
                &gens,
            ),
            rng,
        )?;

        // Prove that the amount is not negative and
        // prove that the sender has enough funds.
        let updated_balance_blinding = balance_refresh_enc_blinding - amount_enc_blinding;
        let range_proofs = InRangeProof::prove_multiple(
            &gens,
            &mut transcript,
            &[amount.into(), (sender_balance - amount).into()],
            &[amount_enc_blinding, updated_balance_blinding],
            BALANCE_RANGE,
            rng,
        )?;

        let inner = ConfidentialTransferInnerProof {
            amount_equal_cipher_proof,
            range_proofs,
            balance_refreshed_same_proof,
            refreshed_enc_balance,
        };
        Ok(Self {
            amounts,
            encoded_inner_proof: inner.encode(),
        })
    }

    /// Verify the ZK-proofs using only public information.
    pub fn verify<R: RngCore + CryptoRng>(
        &self,
        sender_account: &ElgamalPublicKey,
        sender_init_balance: &CipherText,
        receiver_account: &ElgamalPublicKey,
        auditors_keys: &BTreeSet<ElgamalPublicKey>,
        rng: &mut R,
    ) -> Result<()> {
        let mut transcript = Transcript::new(CONFIDENTIAL_TRANSFER_PROOF_LABEL);
        let gens = &PedersenGens::default();

        // Verify that all auditors' payload is included, and
        // that the auditors' ciphertexts encrypt the same amount as sender's ciphertext.
        let a_len = self.amounts.len() - 2;
        ensure!(a_len <= MAX_AUDITORS as usize, Error::TooManyAuditors);
        ensure!(a_len == auditors_keys.len(), Error::WrongNumberOfAuditors);

        // Collect all public keys (Sender, Receiver, Auditors...).
        let keys = Self::keys(sender_account, receiver_account, auditors_keys)?;
        // Ensure that the transaction amount was encrypyted with all keys.
        ensure!(
            keys.len() == self.amounts.len(),
            Error::WrongNumberOfAuditors
        );

        // Decode the inner proof.
        let inner = self.inner_proof()?;

        // Verify that the encrypted amounts are equal.
        single_property_verifier_with_transcript(
            &mut transcript,
            &CipherTextSameValueVerifier::new(keys, self.amounts.ciphertexts(), &gens),
            &inner.amount_equal_cipher_proof,
        )?;

        // verify that the balance refreshment was done correctly.
        single_property_verifier_with_transcript(
            &mut transcript,
            &CipherTextRefreshmentVerifier::new(
                *sender_account,
                *sender_init_balance,
                inner.refreshed_enc_balance,
                &gens,
            ),
            &inner.balance_refreshed_same_proof,
        )?;

        // Verify that the amount is not negative and
        // verify that the balance has enough fund.
        let amount_commitment = *self.amounts.y;
        let updated_balance = inner.refreshed_enc_balance - self.sender_amount();
        let updated_balance_commitment = updated_balance.y.compress();
        inner.range_proofs.verify_multiple(
            &gens,
            &mut transcript,
            &[amount_commitment, updated_balance_commitment],
            BALANCE_RANGE,
            rng,
        )?;

        Ok(())
    }

    /// Receiver verify the transaction amount using their private key.
    pub fn receiver_verify(
        &self,
        receiver_account: ElgamalKeys,
        expected_amount: Option<Balance>,
    ) -> Result<Balance> {
        let enc_amount = self.receiver_amount();
        let amount = match expected_amount {
            Some(expected_amount) => {
                // Check that the amount is correct.
                receiver_account
                    .verify(&enc_amount, &expected_amount.into())
                    .map_err(|_| Error::TransactionAmountMismatch { expected_amount })?;
                expected_amount
            }
            None => {
                // Decrypt the transaction amount using the receiver's secret.
                receiver_account
                    .decrypt_with_hint(&enc_amount, 0, MAX_TOTAL_SUPPLY)
                    .ok_or(Error::CipherTextDecryptionError)?
            }
        };

        Ok(amount)
    }

    /// Verify the initialized transaction.
    /// Audit the sender's encrypted amount.
    pub fn auditor_verify(
        &self,
        auditor_idx: u8,
        auditor_enc_key: &ElgamalKeys,
        expected_amount: Option<Balance>,
    ) -> Result<Balance> {
        self.auditor_verify_with_limit(
            auditor_idx,
            auditor_enc_key,
            expected_amount,
            Balance::max_value(),
        )
    }

    /// Verify the initialized transaction.
    /// Audit the sender's encrypted amount.
    pub fn auditor_verify_with_limit(
        &self,
        auditor_idx: u8,
        auditor_enc_key: &ElgamalKeys,
        expected_amount: Option<Balance>,
        limit: Balance,
    ) -> Result<Balance> {
        let amount_idx = (auditor_idx + 2) as usize;
        if amount_idx >= self.amounts.len() {
            return Err(Error::AuditorVerifyError);
        }
        let enc_amount = self.amount(amount_idx.into());
        let amount = match expected_amount {
            Some(expected_amount) => {
                // Check that the amount is correct.
                auditor_enc_key
                    .verify(&enc_amount, &expected_amount.into())
                    .map_err(|_| Error::TransactionAmountMismatch { expected_amount })?;
                expected_amount
            }
            None => {
                // Decrypt the amount.
                auditor_enc_key
                    .decrypt_with_hint(&enc_amount, 0, limit)
                    .ok_or_else(|| Error::AuditorVerifyError)?
            }
        };
        Ok(amount)
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

    pub fn auditor_count(&self) -> usize {
        self.amounts.len() - 2
    }

    pub fn inner_proof(&self) -> Result<ConfidentialTransferInnerProof> {
        Ok(ConfidentialTransferInnerProof::decode(
            &mut self.encoded_inner_proof.as_slice(),
        )?)
    }

    pub(crate) fn keys(
        sender_key: &ElgamalPublicKey,
        receiver_key: &ElgamalPublicKey,
        auditors_keys: &BTreeSet<ElgamalPublicKey>,
    ) -> Result<Vec<ElgamalPublicKey>> {
        ensure!(
            auditors_keys.len() <= MAX_AUDITORS as usize,
            Error::TooManyAuditors
        );
        // All public keys.
        let mut keys = Vec::with_capacity(auditors_keys.len() + 2);
        keys.push(*sender_key);
        keys.push(*receiver_key);
        for auditor in auditors_keys {
            keys.push(*auditor);
        }

        Ok(keys)
    }
}

/// Holds the zk-proofs of the confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode, Debug)]
pub struct ConfidentialTransferInnerProof {
    /// ZK-proof that all encrypted transaction amounts in `amounts` is the same value.
    pub amount_equal_cipher_proof: CipherTextSameValueProof,
    /// The sender's balance re-encrypted using a new blinding.
    ///
    /// This encrypted value is needed for the "Enough funds" range proof, because the
    /// blinding value needs to be known and we don't want the users to have to keep
    /// an updated copy of the blinding value.
    pub refreshed_enc_balance: CipherText,
    /// ZK-proof that `refreshed_enc_balance` encrypts the same value as the sender's balance.
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    /// Bulletproof range proofs for "Non negative amount" and "Enough funds".
    pub range_proofs: InRangeProof,
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{elgamal::ElgamalSecretKey, CipherText, ElgamalKeys, ElgamalPublicKey, Scalar};
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
        receiver_key: ElgamalPublicKey,
        balance: Balance,
        rng: &mut R,
    ) -> Result<CipherText> {
        let (_, enc_balance) = receiver_key.encrypt_value(Scalar::from(balance), rng);

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

        let auditor_keys = BTreeSet::from([mediator_account.public]);
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
        ctx_init_data
            .receiver_verify(receiver_account.clone(), Some(amount))
            .unwrap();

        // Justify the transaction
        let _result = ctx_init_data
            .auditor_verify(0, &mediator_account, None)
            .unwrap();

        assert!(ctx_init_data
            .verify(
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
        let updated_sender_balance = sender_init_balance - ctx_init_data.sender_amount();
        let updated_receiver_balance = receiver_init_balance + ctx_init_data.receiver_amount();

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
        sender_auditor_list: &[ElgamalPublicKey],
        mediator_auditor_list: &[ElgamalPublicKey],
        mediator_check_fails: bool,
        validator_auditor_list: &[ElgamalPublicKey],
        validator_check_fails: bool,
        auditors_list: &[ElgamalKeys],
    ) {
        let mut sender_auditor_list = BTreeSet::from_iter(sender_auditor_list.iter().copied());
        let mut mediator_auditor_list = BTreeSet::from_iter(mediator_auditor_list.iter().copied());
        let mut validator_auditor_list =
            BTreeSet::from_iter(validator_auditor_list.iter().copied());
        let mut auditors_list = Vec::from(auditors_list);
        let sender_balance = 500;
        let receiver_balance = 0;
        let amount = 400;

        let mut rng = StdRng::from_seed([19u8; 32]);

        let mediator_enc_keys = mock_gen_enc_key_pair(140u8);
        sender_auditor_list.insert(mediator_enc_keys.public);
        mediator_auditor_list.insert(mediator_enc_keys.public);
        validator_auditor_list.insert(mediator_enc_keys.public);
        auditors_list.push(mediator_enc_keys.clone());
        auditors_list.sort_by_key(|a| a.public);
        let mediator_id = sender_auditor_list
            .iter()
            .position(|&p| p == mediator_enc_keys.public)
            .unwrap_or_default() as u8;

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
        ctx_init
            .receiver_verify(receiver_account.clone(), Some(amount))
            .unwrap();

        // Justify the transaction
        let v_amount = ctx_init
            .auditor_verify(mediator_id, &mediator_enc_keys, None)
            .unwrap();
        assert_eq!(amount, v_amount);

        let result = ctx_init.verify(
            &sender_account.public,
            &sender_init_balance,
            &receiver_account.public,
            &mediator_auditor_list,
            &mut rng,
        );
        eprintln!("-- mediator res = {result:?}");
        if mediator_check_fails {
            assert_err!(result, Error::WrongNumberOfAuditors);
            return;
        }
        assert!(result.is_ok());

        let result = ctx_init.verify(
            &sender_account.public,
            &sender_init_balance,
            &receiver_account.public,
            &validator_auditor_list,
            &mut rng,
        );
        eprintln!("-- validator res = {result:?}");

        if validator_check_fails {
            assert_err!(result, Error::WrongNumberOfAuditors);
            return;
        }
        assert!(result.is_ok());

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        let updated_sender_balance = sender_init_balance - ctx_init.sender_amount();
        let updated_receiver_balance = receiver_init_balance + ctx_init.receiver_amount();

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
        for (idx, auditor) in auditors_list.iter().enumerate() {
            let v_amount = ctx_init.auditor_verify(idx as u8, &auditor, None).unwrap();
            assert_eq!(amount, v_amount);
        }
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_transaction_auditor() {
        // Make imaginary auditors.
        let auditors_num = MAX_AUDITORS - 1;
        let auditors_secret_vec: Vec<ElgamalKeys> = (0..auditors_num)
            .map(|index| mock_gen_enc_key_pair(index as u8))
            .collect();
        let auditors_secret_list = auditors_secret_vec.as_slice();

        let auditors_vec: Vec<ElgamalPublicKey> =
            auditors_secret_vec.iter().map(|a| a.public).collect();

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
            auditors_vec[5],
            auditors_vec[0],
            auditors_vec[2],
            auditors_vec[3],
            auditors_vec[6],
            auditors_vec[1],
            auditors_vec[4],
        ];
        let validator_auditor_list = vec![
            auditors_vec[2],
            auditors_vec[6],
            auditors_vec[3],
            auditors_vec[0],
            auditors_vec[4],
            auditors_vec[5],
            auditors_vec[1],
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
        let four_auditor_list = vec![auditors_vec[0], auditors_vec[2]];
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
