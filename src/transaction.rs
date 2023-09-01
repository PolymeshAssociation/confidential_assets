use crate::{
    elgamal::{
        CipherText, CipherTextWithHint, CommitmentWitness,
        ElgamalPublicKey,
        encrypt_using_two_pub_keys,
    },
    errors::{Error, Result},
    proofs::{
        bulletproofs::PedersenGens,
        ciphertext_refreshment_proof::{
            CipherTextRefreshmentProverAwaitingChallenge, CipherTextRefreshmentVerifier,
            CipherEqualSamePubKeyProof,
        },
        correctness_proof::{CorrectnessProof, CorrectnessProverAwaitingChallenge, CorrectnessVerifier},
        encrypting_same_value_proof::{
            CipherEqualDifferentPubKeyProof,
            EncryptingSameValueProverAwaitingChallenge, EncryptingSameValueVerifier,
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

// -------------------------------------------------------------------------------------
// -                       Confidential Transfer Transaction                           -
// -------------------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditorId(#[codec(compact)] pub u32);

#[derive(Clone, Debug)]
pub enum AmountSource<'a> {
    Encrypted(&'a ElgamalKeys),
    Amount(Balance),
}

impl From<Balance> for AmountSource<'_> {
    fn from(val: Balance) -> Self {
        Self::Amount(val)
    }
}

impl AmountSource<'_> {
    pub fn get_amount(&self, enc_amount: Option<&CipherTextWithHint>) -> Result<Balance> {
        match (self, enc_amount) {
            (Self::Amount(amount), _) => Ok(*amount),
            (Self::Encrypted(keys), Some(enc_amount)) => {
                Ok(keys.secret.const_time_decrypt(enc_amount)?)
            }
            _ => Err(Error::CipherTextDecryptionError.into()),
        }
    }
}

#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditorPayload {
    pub encrypted_amount: CipherTextWithHint,
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
}

/// Holds the memo for confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransferTxMemo {
    pub enc_amount_using_sender: CipherText,
    pub enc_amount_using_receiver: CipherText,
    pub refreshed_enc_balance: CipherText,
    pub enc_amount_for_mediator: Option<CipherTextWithHint>,
}

/// Holds the proofs and memo of the confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConfidentialTransferProof {
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub non_neg_amount_proof: InRangeProof,
    pub enough_fund_proof: InRangeProof,
    pub memo: TransferTxMemo,
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub amount_correctness_proof: CorrectnessProof,
    pub auditors: BTreeMap<AuditorId, AuditorPayload>,
}

impl ConfidentialTransferProof {
    /// Create a confidential asset transfer proof.
    pub fn new<T: RngCore + CryptoRng>(
        sender_account: &ElgamalKeys,
        sender_init_balance: &CipherText,
        sender_balance: Balance,
        receiver_pub_key: &ElgamalPublicKey,
        mediator_pub_key: Option<&ElgamalPublicKey>,
        auditors_enc_pub_keys: &[(AuditorId, ElgamalPublicKey)],
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
            .secret
            .verify(sender_init_balance, &sender_balance.into())?;

        // Prove that the amount is not negative.
        let witness = CommitmentWitness::new(amount.into(), Scalar::random(rng));
        let amount_enc_blinding = witness.blinding();

        let non_neg_amount_proof =
            InRangeProof::prove(amount.into(), amount_enc_blinding, BALANCE_RANGE, rng)?;

        // Prove that the amount encrypted under different public keys are the same.
        let (sender_new_enc_amount, receiver_new_enc_amount) =
            encrypt_using_two_pub_keys(&witness, sender_account.public, *receiver_pub_key);
        let gens = PedersenGens::default();
        let amount_equal_cipher_proof = single_property_prover(
            EncryptingSameValueProverAwaitingChallenge {
                pub_key1: sender_account.public,
                pub_key2: *receiver_pub_key,
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

        let enc_amount_for_mediator = if let Some(mediator_pub_key) = mediator_pub_key {
            let amount_witness_blinding_for_mediator = Scalar::random(rng);
            let amount_witness_for_mediator =
                CommitmentWitness::new(amount.into(), amount_witness_blinding_for_mediator);
            Some(mediator_pub_key.const_time_encrypt(&amount_witness_for_mediator, rng))
        } else {
            None
        };

        let amount_correctness_proof = single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: sender_account.public,
                w: witness.clone(),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Add the necessary payload for auditors.
        let auditors = auditors_enc_pub_keys
            .iter()
            .map(|(auditor_id, auditor_enc_pub_key)| -> Result<_> {
                let encrypted_amount = auditor_enc_pub_key.const_time_encrypt(&witness, rng);

                // Prove that the sender and auditor's ciphertexts are encrypting the same
                // commitment witness.
                let amount_equal_cipher_proof = single_property_prover(
                    EncryptingSameValueProverAwaitingChallenge {
                        pub_key1: sender_account.public,
                        pub_key2: *auditor_enc_pub_key,
                        w: witness.clone(),
                        pc_gens: &gens,
                    },
                    rng,
                )?;

                Ok((*auditor_id, AuditorPayload {
                    encrypted_amount,
                    amount_equal_cipher_proof,
                }))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(Self {
            amount_equal_cipher_proof,
            non_neg_amount_proof,
            enough_fund_proof,
            balance_refreshed_same_proof,
            amount_correctness_proof,
            memo: TransferTxMemo {
                enc_amount_using_sender: sender_new_enc_amount,
                enc_amount_using_receiver: receiver_new_enc_amount,
                refreshed_enc_balance,
                enc_amount_for_mediator,
            },
            auditors,
        })
    }

    /// Receiver verify the transaction amount using their private key.
    pub fn receiver_verify(
        &self,
        receiver_account: ElgamalKeys,
        amount: Balance,
    ) -> Result<()> {
        // Check that the amount is correct.
        receiver_account
            .secret
            .verify(&self.memo.enc_amount_using_receiver, &amount.into())
            .map_err(|_| Error::TransactionAmountMismatch {
                expected_amount: amount,
            })?;

        Ok(())
    }

    /// Receiver verify the transaction amount using their private key.
    pub fn mediator_verify<R: RngCore + CryptoRng>(
        &self,
        amount_source: AmountSource,
        sender_account: &ElgamalPublicKey,
        sender_init_balance: &CipherText,
        receiver_account: &ElgamalPublicKey,
        auditors_enc_pub_keys: &[(AuditorId, ElgamalPublicKey)],
        rng: &mut R,
    ) -> Result<()> {
        // Verify sender's part of the transaction.
        // This includes checking the auditors' payload.
        self.verify(
            sender_account,
            sender_init_balance,
            receiver_account,
            auditors_enc_pub_keys,
            rng,
        )?;

        // Verify that the encrypted amount is correct.
        let amount = amount_source.get_amount(self.memo.enc_amount_for_mediator.as_ref())?;
        self.verify_amount_correctness(amount, sender_account)?;

        Ok(())
    }

    /// Verify the ZK-proofs using only public information.
    pub fn verify<R: RngCore + CryptoRng>(
        &self,
        sender_account: &ElgamalPublicKey,
        sender_init_balance: &CipherText,
        receiver_account: &ElgamalPublicKey,
        auditors_enc_pub_keys: &[(AuditorId, ElgamalPublicKey)],
        rng: &mut R,
    ) -> Result<()> {
        let gens = &PedersenGens::default();

        // Verify that the encrypted amounts are equal.
        single_property_verifier(
            &EncryptingSameValueVerifier {
                pub_key1: *sender_account,
                pub_key2: *receiver_account,
                cipher1: self.memo.enc_amount_using_sender,
                cipher2: self.memo.enc_amount_using_receiver,
                pc_gens: &gens,
            },
            self.amount_equal_cipher_proof,
        )?;

        // Verify that the amount is not negative.
        let commitment = self.memo.enc_amount_using_sender.y.compress();
        self.non_neg_amount_proof.verify(&commitment, BALANCE_RANGE, rng)?;

        // verify that the balance refreshment was done correctly.
        single_property_verifier(
            &CipherTextRefreshmentVerifier::new(
                *sender_account,
                *sender_init_balance,
                self.memo.refreshed_enc_balance,
                &gens,
            ),
            self.balance_refreshed_same_proof,
        )?;

        // Verify that the balance has enough fund.
        let updated_balance = self.memo.refreshed_enc_balance - self.memo.enc_amount_using_sender;
        let commitment = updated_balance.y.compress();
        self.enough_fund_proof.verify(&commitment, BALANCE_RANGE, rng)?;

        // Verify that all auditors' payload is included, and
        // that the auditors' ciphertexts encrypt the same amount as sender's ciphertext.
        ensure!(
            self.auditors.len() == auditors_enc_pub_keys.len(),
            Error::AuditorPayloadError
        );
    
        for (auditor_id, auditor_pub_key) in auditors_enc_pub_keys {
            match self.auditors.get(auditor_id) {
                Some(auditor) => {
                    // Verify that the encrypted amounts are equal.
                    single_property_verifier(
                        &EncryptingSameValueVerifier {
                            pub_key1: *sender_account,
                            pub_key2: *auditor_pub_key,
                            cipher1: self.memo.enc_amount_using_sender,
                            cipher2: auditor.encrypted_amount.elgamal_cipher,
                            pc_gens: &gens,
                        },
                        auditor.amount_equal_cipher_proof,
                    )?;
                }
                None => {
                    return Err(Error::AuditorPayloadError);
                }
            }
        }

        Ok(())
    }

    /// Verify the initialized transaction.
    /// Audit the sender's encrypted amount.
    pub fn auditor_verify(
        &self,
        sender_account: &ElgamalPublicKey,
        (auditor_id, auditor_enc_key): &(AuditorId, ElgamalKeys),
    ) -> Result<()> {
        match self.auditors.get(auditor_id) {
            Some(auditor) => {
                let amount = auditor_enc_key
                    .secret
                    .const_time_decrypt(&auditor.encrypted_amount)?;

                // Verify that the encrypted amount is correct.
                self.verify_amount_correctness(amount, sender_account)?;
                Ok(())
            }
            None => {
                Err(Error::AuditorPayloadError)
            }
        }
    }

    pub fn verify_amount_correctness(
        &self,
        amount: Balance,
        sender_account: &ElgamalPublicKey,
    ) -> Result<()> {
        let gens = &PedersenGens::default();
    
        // Verify that the encrypted amount is correct.
        single_property_verifier(
            &CorrectnessVerifier {
                value: amount.into(),
                pub_key: *sender_account,
                cipher: self.memo.enc_amount_using_sender,
                pc_gens: &gens,
            },
            self.amount_correctness_proof,
        )?;
    
        Ok(())
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
        proofs::{
            ciphertext_refreshment_proof::CipherEqualSamePubKeyProof,
            correctness_proof::CorrectnessProof,
            encrypting_same_value_proof::CipherEqualDifferentPubKeyProof,
            range_proof::InRangeProof,
        },
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

    fn mock_ctx_init_memo<R: RngCore + CryptoRng>(
        receiver_pub_key: ElgamalPublicKey,
        amount: Balance,
        rng: &mut R,
    ) -> TransferTxMemo {
        let (_, enc_amount_using_receiver) = receiver_pub_key.encrypt_value(amount.into(), rng);
        TransferTxMemo {
            enc_amount_using_sender: CipherText::default(),
            enc_amount_using_receiver,
            refreshed_enc_balance: CipherText::default(),
            enc_amount_for_mediator: None,
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

    fn mock_ctx_init_data<R: RngCore + CryptoRng>(
        receiver_pub_key: ElgamalPublicKey,
        expected_amount: Balance,
        rng: &mut R,
    ) -> ConfidentialTransferProof {
        ConfidentialTransferProof {
            memo: mock_ctx_init_memo(receiver_pub_key, expected_amount, rng),
            amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof::default(),
            non_neg_amount_proof: InRangeProof::build(rng),
            enough_fund_proof: InRangeProof::build(rng),
            balance_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
            amount_correctness_proof: CorrectnessProof::default(),
            auditors: BTreeMap::default(),
        }
    }

    // -------------------------- tests -----------------------

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_success() {
        let expected_amount = 10;
        let balance = 0;
        let mut rng = StdRng::from_seed([17u8; 32]);

        let receiver_account = mock_gen_enc_key_pair(17u8);

        let ctx_init_data = mock_ctx_init_data(receiver_account.public, expected_amount, &mut rng);
        let _enc_balance = mock_gen_account(receiver_account.public, balance, &mut rng).unwrap();

        let result =
            ctx_init_data.receiver_verify(receiver_account, expected_amount);

        result.unwrap();
        // Correctness of the proof will be verified in the verify function
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_amount_mismatch_error() {
        let expected_amount = 10;
        let received_amount = 20;
        let mut rng = StdRng::from_seed([17u8; 32]);

        let receiver_account = mock_gen_enc_key_pair(17u8);

        let ctx_init_data = mock_ctx_init_data(receiver_account.public, received_amount, &mut rng);

        let result =
            ctx_init_data.receiver_verify(receiver_account, expected_amount);

        assert_err!(result, Error::TransactionAmountMismatch { expected_amount });
    }

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

        // Create the transaction and check its result and state
        let result = ConfidentialTransferProof::new(
            &sender_account,
            &sender_init_balance,
            sender_balance,
            &receiver_account.public,
            Some(&mediator_account.public),
            &[],
            amount,
            &mut rng,
        );
        let ctx_init_data = result.unwrap();

        // Finalize the transaction and check its state.
        ctx_init_data.receiver_verify(receiver_account.clone(), amount)
            .unwrap();

        // Justify the transaction
        let _result = ctx_init_data.mediator_verify(
                AmountSource::Encrypted(&mediator_account),
                &sender_account.public,
                &sender_init_balance,
                &receiver_account.public,
                &[],
                &mut rng,
            )
            .unwrap();

        assert!(ctx_init_data.verify(
                &sender_account.public,
                &sender_init_balance,
                &receiver_account.public,
                &[],
                &mut rng,
            )
            .is_ok());

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        let updated_sender_balance =
            sender_init_balance - ctx_init_data.memo.enc_amount_using_sender;
        let updated_receiver_balance =
            receiver_init_balance + ctx_init_data.memo.enc_amount_using_receiver;

        assert!(sender_account
            .secret
            .verify(&updated_sender_balance, &(sender_balance - amount).into())
            .is_ok());
        assert!(receiver_account
            .secret
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
        let sender_balance = 500;
        let receiver_balance = 0;
        let amount = 400;

        let mut rng = StdRng::from_seed([19u8; 32]);

        let mediator_enc_keys = mock_gen_enc_key_pair(140u8);

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
                Some(&mediator_enc_keys.public),
                sender_auditor_list,
                amount,
                &mut rng,
            )
            .unwrap();

        // Finalize the transaction and check its state
        ctx_init.receiver_verify(receiver_account.clone(), amount)
            .unwrap();

        // Justify the transaction
        let result = ctx_init.mediator_verify(
            AmountSource::Encrypted(&mediator_enc_keys),
            &sender_account.public,
            &sender_init_balance,
            &receiver_account.public,
            mediator_auditor_list,
            &mut rng,
        );

        if mediator_check_fails {
            assert_err!(result, Error::AuditorPayloadError);
            return;
        }

        let _ctx_just = result.unwrap();
        let result = ctx_init.verify(
            &sender_account.public,
            &sender_init_balance,
            &receiver_account.public,
            validator_auditor_list,
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
        let updated_sender_balance = sender_init_balance - ctx_init.memo.enc_amount_using_sender;
        let updated_receiver_balance =
            receiver_init_balance + ctx_init.memo.enc_amount_using_receiver;

        assert!(sender_account
            .secret
            .verify(&updated_sender_balance, &(sender_balance - amount).into())
            .is_ok());
        assert!(receiver_account
            .secret
            .verify(
                &updated_receiver_balance,
                &(receiver_balance + amount).into()
            )
            .is_ok());

        // ----------------------- Auditing
        let _ = auditors_list.iter().map(|auditor| {
            assert!(ctx_init
                .auditor_verify(
                    &sender_account.public,
                    auditor,
                )
                .is_ok());
        });
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
