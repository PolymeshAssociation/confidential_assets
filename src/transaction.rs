use crate::{
    elgamal::{encrypt_using_two_pub_keys, CommitmentWitness},
    errors::{ErrorKind, Fallible},
    proofs::{
        bulletproofs::PedersenGens,
        ciphertext_refreshment_proof::{
            CipherTextRefreshmentProverAwaitingChallenge, CipherTextRefreshmentVerifier,
        },
        correctness_proof::{CorrectnessProverAwaitingChallenge, CorrectnessVerifier},
        encrypting_same_value_proof::{
            EncryptingSameValueProverAwaitingChallenge, EncryptingSameValueVerifier,
        },
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
        range_proof::{prove_within_range, verify_within_range},
    },
    Account, AmountSource, AuditorId, AuditorPayload, Balance, EncryptedAmount, EncryptionKeys,
    EncryptionPubKey, FinalizedTransferTx, InitializedTransferTx, JustifiedTransferTx, PubAccount,
    Scalar, TransferTransactionAuditor, TransferTransactionMediator, TransferTransactionReceiver,
    TransferTransactionSender, TransferTransactionVerifier, TransferTxMemo, TransferTxState,
    TxSubstate, BALANCE_RANGE,
};

use rand_core::{CryptoRng, RngCore};
use sp_std::vec::Vec;
use zeroize::Zeroizing;

// -------------------------------------------------------------------------------------
// -                                    Sender                                         -
// -------------------------------------------------------------------------------------

/// The sender of a confidential transaction. Sender creates a transaction
/// and performs initial proofs.
#[derive(Clone, Debug)]
pub struct CtxSender;

impl TransferTransactionSender for CtxSender {
    fn create_transaction<T: RngCore + CryptoRng>(
        &self,
        sender_account: &Account,
        sender_init_balance: &EncryptedAmount,
        sender_balance: Balance,
        receiver_pub_account: &PubAccount,
        mediator_pub_key: Option<&EncryptionPubKey>,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedTransferTx> {
        let sender_enc_keys = &sender_account.secret.enc_keys;
        let receiver_pub_key = receiver_pub_account.owner_enc_pub_key;

        // Ensure the sender has enough funds.
        ensure!(
            sender_balance >= amount,
            ErrorKind::NotEnoughFund {
                balance: sender_balance,
                transaction_amount: amount
            }
        );
        // Verify the sender's balance.
        sender_enc_keys
            .secret
            .verify(sender_init_balance, &sender_balance.into())?;

        // Prove that the amount is not negative.
        let witness = CommitmentWitness::new(amount.into(), Scalar::random(rng));
        let amount_enc_blinding = witness.blinding();

        let non_neg_amount_proof =
            prove_within_range(amount.into(), amount_enc_blinding, BALANCE_RANGE, rng)?;

        // Prove that the amount encrypted under different public keys are the same.
        let (sender_new_enc_amount, receiver_new_enc_amount) =
            encrypt_using_two_pub_keys(&witness, sender_enc_keys.public, receiver_pub_key);
        let gens = PedersenGens::default();
        let amount_equal_cipher_proof = single_property_prover(
            EncryptingSameValueProverAwaitingChallenge {
                pub_key1: sender_enc_keys.public,
                pub_key2: receiver_pub_key,
                w: Zeroizing::new(witness.clone()),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Refresh the encrypted balance and prove that the refreshment was done
        // correctly.
        let balance_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_balance = sender_init_balance.refresh_with_hint(
            &sender_enc_keys.secret,
            balance_refresh_enc_blinding,
            &sender_balance.into(),
        )?;

        let balance_refreshed_same_proof = single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                sender_enc_keys.secret.clone(),
                *sender_init_balance,
                refreshed_enc_balance,
                &gens,
            ),
            rng,
        )?;

        // Prove that the sender has enough funds.
        let blinding = balance_refresh_enc_blinding - amount_enc_blinding;
        let enough_fund_proof = prove_within_range(
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
                pub_key: sender_enc_keys.public,
                w: witness.clone(),
                pc_gens: &gens,
            },
            rng,
        )?;

        // Add the necessary payload for auditors.
        let auditors_payload = add_transaction_auditor(
            auditors_enc_pub_keys,
            &sender_enc_keys.public,
            &witness,
            rng,
        )?;

        Ok(InitializedTransferTx {
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
            auditors_payload,
        })
    }
}

fn add_transaction_auditor<T: RngCore + CryptoRng>(
    auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
    sender_enc_pub_key: &EncryptionPubKey,
    amount_witness: &CommitmentWitness,
    rng: &mut T,
) -> Fallible<Vec<AuditorPayload>> {
    let gens = PedersenGens::default();

    let mut payload_vec: Vec<AuditorPayload> = Vec::with_capacity(auditors_enc_pub_keys.len());
    // Add the required payload for the auditors.
    let _: Fallible<()> = auditors_enc_pub_keys
        .iter()
        .map(|(auditor_id, auditor_enc_pub_key)| {
            let encrypted_amount = auditor_enc_pub_key.const_time_encrypt(amount_witness, rng);

            // Prove that the sender and auditor's ciphertexts are encrypting the same
            // commitment witness.
            let amount_equal_cipher_proof = single_property_prover(
                EncryptingSameValueProverAwaitingChallenge {
                    pub_key1: *sender_enc_pub_key,
                    pub_key2: *auditor_enc_pub_key,
                    w: Zeroizing::new(amount_witness.clone()),
                    pc_gens: &gens,
                },
                rng,
            )?;

            let payload = AuditorPayload {
                auditor_id: *auditor_id,
                encrypted_amount,
                amount_equal_cipher_proof,
            };

            payload_vec.push(payload);
            Ok(())
        })
        .collect();

    Ok(payload_vec)
}

// ------------------------------------------------------------------------------------------------
// -                                          Receiver                                            -
// ------------------------------------------------------------------------------------------------

/// The receiver of a confidential transaction. Receiver finalizes and processes
/// transaction.
#[derive(Clone, Debug)]
pub struct CtxReceiver;

impl TransferTransactionReceiver for CtxReceiver {
    fn finalize_transaction(
        &self,
        init_tx: &InitializedTransferTx,
        receiver_account: Account,
        amount: Balance,
    ) -> Fallible<FinalizedTransferTx> {
        // Check that the amount is correct.
        receiver_account
            .secret
            .enc_keys
            .secret
            .verify(&init_tx.memo.enc_amount_using_receiver, &amount.into())
            .map_err(|_| ErrorKind::TransactionAmountMismatch {
                expected_amount: amount,
            })?;

        Ok(FinalizedTransferTx {})
    }
}

// ------------------------------------------------------------------------------------------------
// -                                           Mediator                                           -
// ------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CtxMediator;

impl TransferTransactionMediator for CtxMediator {
    fn justify_transaction<R: RngCore + CryptoRng>(
        &self,
        init_tx: &InitializedTransferTx,
        amount_source: AmountSource,
        sender_account: &PubAccount,
        sender_init_balance: &EncryptedAmount,
        receiver_account: &PubAccount,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        rng: &mut R,
    ) -> Fallible<JustifiedTransferTx> {
        // Verify sender's part of the transaction.
        // This includes checking the auditors' payload.
        let _ = verify_initialized_transaction(
            &init_tx,
            sender_account,
            sender_init_balance,
            receiver_account,
            auditors_enc_pub_keys,
            rng,
        )?;

        // Verify that the encrypted amount is correct.
        let amount = amount_source.get_amount(init_tx.memo.enc_amount_for_mediator.as_ref())?;
        verify_amount_correctness(&init_tx, amount, sender_account)?;

        Ok(JustifiedTransferTx {})
    }
}

// ------------------------------------------------------------------------------------------------
// -                                          Validator                                           -
// ------------------------------------------------------------------------------------------------

/// Transaction Validator.
#[derive(Clone, Debug)]
pub struct TransactionValidator;

impl TransferTransactionVerifier for TransactionValidator {
    fn verify_transaction<R: RngCore + CryptoRng>(
        &self,
        init_tx: &InitializedTransferTx,
        sender_account: &PubAccount,
        sender_init_balance: &EncryptedAmount,
        receiver_account: &PubAccount,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        rng: &mut R,
    ) -> Fallible<()> {
        verify_initialized_transaction(
            init_tx,
            sender_account,
            sender_init_balance,
            receiver_account,
            auditors_enc_pub_keys,
            rng,
        )?;

        Ok(())
    }
}

pub fn verify_initialized_transaction<R: RngCore + CryptoRng>(
    transaction: &InitializedTransferTx,
    sender_account: &PubAccount,
    sender_init_balance: &EncryptedAmount,
    receiver_account: &PubAccount,
    auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
    rng: &mut R,
) -> Fallible<TransferTxState> {
    verify_initial_transaction_proofs(
        transaction,
        sender_account,
        sender_init_balance,
        receiver_account,
        auditors_enc_pub_keys,
        rng,
    )?;

    Ok(TransferTxState::Initialization(TxSubstate::Validated))
}

fn verify_initial_transaction_proofs<R: RngCore + CryptoRng>(
    transaction: &InitializedTransferTx,
    sender_account: &PubAccount,
    sender_init_balance: &EncryptedAmount,
    receiver_account: &PubAccount,
    auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
    rng: &mut R,
) -> Fallible<()> {
    let memo = &transaction.memo;
    let init_data = &transaction;
    let gens = &PedersenGens::default();

    // Verify that the encrypted amounts are equal.
    single_property_verifier(
        &EncryptingSameValueVerifier {
            pub_key1: sender_account.owner_enc_pub_key,
            pub_key2: receiver_account.owner_enc_pub_key,
            cipher1: memo.enc_amount_using_sender,
            cipher2: memo.enc_amount_using_receiver,
            pc_gens: &gens,
        },
        init_data.amount_equal_cipher_proof,
    )?;

    // Verify that the amount is not negative.
    verify_within_range(&init_data.non_neg_amount_proof, rng)?;

    // verify that the balance refreshment was done correctly.
    single_property_verifier(
        &CipherTextRefreshmentVerifier::new(
            sender_account.owner_enc_pub_key,
            *sender_init_balance,
            memo.refreshed_enc_balance,
            &gens,
        ),
        init_data.balance_refreshed_same_proof,
    )?;

    // Verify that the balance has enough fund.
    verify_within_range(&init_data.enough_fund_proof, rng)?;

    // Verify that all auditors' payload is included, and
    // that the auditors' ciphertexts encrypt the same amount as sender's ciphertext.
    verify_auditor_payload(
        &init_data.auditors_payload,
        auditors_enc_pub_keys,
        sender_account.owner_enc_pub_key,
        init_data.memo.enc_amount_using_sender,
    )?;

    Ok(())
}

pub fn verify_amount_correctness(
    init_tx: &InitializedTransferTx,
    amount: Balance,
    sender_account: &PubAccount,
) -> Fallible<()> {
    let gens = &PedersenGens::default();

    // Verify that the encrypted amount is correct.
    single_property_verifier(
        &CorrectnessVerifier {
            value: amount.into(),
            pub_key: sender_account.owner_enc_pub_key,
            cipher: init_tx.memo.enc_amount_using_sender,
            pc_gens: &gens,
        },
        init_tx.amount_correctness_proof,
    )?;

    Ok(())
}

fn verify_auditor_payload(
    auditors_payload: &[AuditorPayload],
    auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
    sender_enc_pub_key: EncryptionPubKey,
    sender_enc_amount: EncryptedAmount,
) -> Fallible<()> {
    ensure!(
        auditors_payload.len() == auditors_enc_pub_keys.len(),
        ErrorKind::AuditorPayloadError
    );

    let gens = &PedersenGens::default();
    let _: Fallible<()> = auditors_enc_pub_keys
        .iter()
        .map(|(auditor_id, auditor_pub_key)| {
            let mut found_auditor = false;
            let _: Fallible<()> = auditors_payload
                .iter()
                .map(|payload| {
                    if *auditor_id == payload.auditor_id {
                        // Verify that the encrypted amounts are equal.
                        single_property_verifier(
                            &EncryptingSameValueVerifier {
                                pub_key1: sender_enc_pub_key,
                                pub_key2: *auditor_pub_key,
                                cipher1: sender_enc_amount,
                                cipher2: payload.encrypted_amount.elgamal_cipher,
                                pc_gens: &gens,
                            },
                            payload.amount_equal_cipher_proof,
                        )?;
                        found_auditor |= true;
                    }
                    Ok(())
                })
                .collect();
            ensure!(found_auditor, ErrorKind::AuditorPayloadError);
            Ok(())
        })
        .collect();

    Ok(())
}

// ------------------------------------------------------------------------------------------------
// -                                          Auditor                                           -
// ------------------------------------------------------------------------------------------------

/// Transaction Validator.
#[derive(Clone, Debug)]
pub struct CtxAuditor;

impl TransferTransactionAuditor for CtxAuditor {
    /// Verify the initialized transaction.
    /// Audit the sender's encrypted amount.
    fn audit_transaction(
        &self,
        init_tx: &InitializedTransferTx,
        sender_account: &PubAccount,
        _receiver_account: &PubAccount,
        auditor_enc_key: &(AuditorId, EncryptionKeys),
    ) -> Fallible<()> {
        // If all checks pass, decrypt the encrypted amount and verify sender's correctness proof.
        let _: Fallible<()> = init_tx
            .auditors_payload
            .iter()
            .map(|payload| {
                if payload.auditor_id == auditor_enc_key.0 {
                    let amount = auditor_enc_key
                        .1
                        .secret
                        .const_time_decrypt(&payload.encrypted_amount)?;

                    // Verify that the encrypted amount is correct.
                    verify_amount_correctness(&init_tx, amount, sender_account)?;
                }
                Ok(())
            })
            .collect();

        Err(ErrorKind::AuditorPayloadError.into())
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
        account::{deposit, withdraw},
        elgamal::ElgamalSecretKey,
        proofs::{
            ciphertext_refreshment_proof::CipherEqualSamePubKeyProof,
            correctness_proof::CorrectnessProof,
            encrypting_same_value_proof::CipherEqualDifferentPubKeyProof,
            range_proof::InRangeProof,
        },
        EncryptedAmount, EncryptionKeys, EncryptionPubKey, Scalar, SecAccount, TransferTxMemo,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rand_core::{CryptoRng, RngCore};
    use wasm_bindgen_test::*;

    // -------------------------- mock helper methods -----------------------

    fn mock_gen_enc_key_pair(seed: u8) -> EncryptionKeys {
        let mut rng = StdRng::from_seed([seed; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        EncryptionKeys {
            public: elg_pub,
            secret: elg_secret,
        }
    }

    fn mock_ctx_init_memo<R: RngCore + CryptoRng>(
        receiver_pub_key: EncryptionPubKey,
        amount: Balance,
        rng: &mut R,
    ) -> TransferTxMemo {
        let (_, enc_amount_using_receiver) = receiver_pub_key.encrypt_value(amount.into(), rng);
        TransferTxMemo {
            enc_amount_using_sender: EncryptedAmount::default(),
            enc_amount_using_receiver,
            refreshed_enc_balance: EncryptedAmount::default(),
            enc_amount_for_mediator: None,
        }
    }

    fn mock_gen_account<R: RngCore + CryptoRng>(
        receiver_enc_pub_key: EncryptionPubKey,
        balance: Balance,
        rng: &mut R,
    ) -> Fallible<(PubAccount, EncryptedAmount)> {
        let (_, enc_balance) = receiver_enc_pub_key.encrypt_value(Scalar::from(balance), rng);

        Ok((
            PubAccount {
                owner_enc_pub_key: receiver_enc_pub_key,
            },
            enc_balance,
        ))
    }

    fn mock_ctx_init_data<R: RngCore + CryptoRng>(
        receiver_pub_key: EncryptionPubKey,
        expected_amount: Balance,
        rng: &mut R,
    ) -> InitializedTransferTx {
        InitializedTransferTx {
            memo: mock_ctx_init_memo(receiver_pub_key, expected_amount, rng),
            amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof::default(),
            non_neg_amount_proof: InRangeProof::build(rng),
            enough_fund_proof: InRangeProof::build(rng),
            balance_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
            amount_correctness_proof: CorrectnessProof::default(),
            auditors_payload: [].to_vec(),
        }
    }

    // -------------------------- tests -----------------------

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_success() {
        let ctx_receiver = CtxReceiver;
        let expected_amount = 10;
        let balance = 0;
        let mut rng = StdRng::from_seed([17u8; 32]);

        let receiver_enc_keys = mock_gen_enc_key_pair(17u8);

        let ctx_init_data = mock_ctx_init_data(receiver_enc_keys.public, expected_amount, &mut rng);
        let (pub_account, _enc_balance) =
            mock_gen_account(receiver_enc_keys.public, balance, &mut rng).unwrap();
        let receiver_account = Account {
            public: pub_account,
            secret: SecAccount {
                enc_keys: receiver_enc_keys,
            },
        };

        let result =
            ctx_receiver.finalize_transaction(&ctx_init_data, receiver_account, expected_amount);

        result.unwrap();
        // Correctness of the proof will be verified in the verify function
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_finalize_ctx_amount_mismatch_error() {
        let ctx_receiver = CtxReceiver;
        let expected_amount = 10;
        let received_amount = 20;
        let balance = 0;
        let mut rng = StdRng::from_seed([17u8; 32]);

        let receiver_enc_keys = mock_gen_enc_key_pair(17u8);

        let ctx_init_data = mock_ctx_init_data(receiver_enc_keys.public, received_amount, &mut rng);
        let receiver_account = Account {
            public: mock_gen_account(receiver_enc_keys.public, balance, &mut rng)
                .unwrap()
                .0,
            secret: SecAccount {
                enc_keys: receiver_enc_keys,
            },
        };

        let result =
            ctx_receiver.finalize_transaction(&ctx_init_data, receiver_account, expected_amount);

        assert_err!(
            result,
            ErrorKind::TransactionAmountMismatch { expected_amount }
        );
    }

    // ------------------------------ Test simple scenarios

    #[test]
    #[wasm_bindgen_test]
    fn test_ctx_create_finalize_validate_success() {
        let sender = CtxSender;
        let receiver = CtxReceiver;
        let mediator = CtxMediator;
        let tx_validator = TransactionValidator;
        let sender_balance = 40;
        let receiver_balance = 0;
        let amount = 30;

        let mut rng = StdRng::from_seed([17u8; 32]);

        let sender_enc_keys = mock_gen_enc_key_pair(10u8);

        let receiver_enc_keys = mock_gen_enc_key_pair(12u8);

        let mediator_enc_keys = mock_gen_enc_key_pair(14u8);

        let (receiver_pub_account, receiver_init_balance) =
            mock_gen_account(receiver_enc_keys.public, receiver_balance, &mut rng).unwrap();
        let receiver_account = Account {
            public: receiver_pub_account,
            secret: SecAccount {
                enc_keys: receiver_enc_keys.clone(),
            },
        };

        let (sender_pub_account, sender_init_balance) =
            mock_gen_account(sender_enc_keys.public, sender_balance, &mut rng).unwrap();
        let sender_account = Account {
            public: sender_pub_account,
            secret: SecAccount {
                enc_keys: sender_enc_keys.clone(),
            },
        };

        // Create the transaction and check its result and state
        let result = sender.create_transaction(
            &sender_account,
            &sender_init_balance,
            sender_balance,
            &receiver_account.public,
            Some(&mediator_enc_keys.public),
            &[],
            amount,
            &mut rng,
        );
        let ctx_init_data = result.unwrap();

        // Finalize the transaction and check its state.
        receiver
            .finalize_transaction(&ctx_init_data, receiver_account.clone(), amount)
            .unwrap();

        // Justify the transaction
        let _result = mediator
            .justify_transaction(
                &ctx_init_data,
                AmountSource::Encrypted(&mediator_enc_keys),
                &sender_account.public,
                &sender_init_balance,
                &receiver_account.public,
                &[],
                &mut rng,
            )
            .unwrap();

        assert!(tx_validator
            .verify_transaction(
                &ctx_init_data,
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
        let updated_sender_balance = withdraw(
            &sender_init_balance,
            &ctx_init_data.memo.enc_amount_using_sender,
        );
        let updated_receiver_balance = deposit(
            &receiver_init_balance,
            &ctx_init_data.memo.enc_amount_using_receiver,
        );

        assert!(sender_enc_keys
            .secret
            .verify(&updated_sender_balance, &(sender_balance - amount).into())
            .is_ok());
        assert!(receiver_enc_keys
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
    ) -> (Account, EncryptedAmount) {
        let mut rng = StdRng::from_seed(seed0);

        let enc_keys = mock_gen_enc_key_pair(seed1);

        let (pub_account, init_balance) =
            mock_gen_account(enc_keys.public, balance, &mut rng).unwrap();

        (
            Account {
                public: pub_account,
                secret: SecAccount { enc_keys },
            },
            init_balance,
        )
    }

    fn test_transaction_auditor_helper(
        sender_auditor_list: &[(AuditorId, EncryptionPubKey)],
        mediator_auditor_list: &[(AuditorId, EncryptionPubKey)],
        mediator_check_fails: bool,
        validator_auditor_list: &[(AuditorId, EncryptionPubKey)],
        validator_check_fails: bool,
        auditors_list: &[(AuditorId, EncryptionKeys)],
    ) {
        let sender = CtxSender;
        let receiver = CtxReceiver;
        let mediator = CtxMediator;
        let validator = TransactionValidator;
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
        let ctx_init = sender
            .create_transaction(
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
        receiver
            .finalize_transaction(&ctx_init, receiver_account.clone(), amount)
            .unwrap();

        // Justify the transaction
        let result = mediator.justify_transaction(
            &ctx_init,
            AmountSource::Encrypted(&mediator_enc_keys),
            &sender_account.public,
            &sender_init_balance,
            &receiver_account.public,
            mediator_auditor_list,
            &mut rng,
        );

        if mediator_check_fails {
            assert_err!(result, ErrorKind::AuditorPayloadError);
            return;
        }

        let _ctx_just = result.unwrap();
        let result = validator.verify_transaction(
            &ctx_init,
            &sender_account.public,
            &sender_init_balance,
            &receiver_account.public,
            validator_auditor_list,
            &mut rng,
        );

        if validator_check_fails {
            assert_err!(result, ErrorKind::AuditorPayloadError);
            return;
        }

        assert!(result.is_ok());

        // ----------------------- Processing
        // Check that the transferred amount is added to the receiver's account balance
        // and subtracted from sender's balance.
        let updated_sender_balance =
            withdraw(&sender_init_balance, &ctx_init.memo.enc_amount_using_sender);
        let updated_receiver_balance = deposit(
            &receiver_init_balance,
            &ctx_init.memo.enc_amount_using_receiver,
        );

        assert!(sender_account
            .secret
            .enc_keys
            .secret
            .verify(&updated_sender_balance, &(sender_balance - amount).into())
            .is_ok());
        assert!(receiver_account
            .secret
            .enc_keys
            .secret
            .verify(
                &updated_receiver_balance,
                &(receiver_balance + amount).into()
            )
            .is_ok());

        // ----------------------- Auditing
        let _ = auditors_list.iter().map(|auditor| {
            let transaction_auditor = CtxAuditor;
            assert!(transaction_auditor
                .audit_transaction(
                    &ctx_init,
                    &sender_account.public,
                    &receiver_account.public,
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
        let auditors_secret_vec: Vec<(AuditorId, EncryptionKeys)> = (0..auditors_num)
            .map(|index| {
                let auditor_keys = mock_gen_enc_key_pair(index as u8);
                (index, auditor_keys)
            })
            .collect();
        let auditors_secret_list = auditors_secret_vec.as_slice();

        let auditors_vec: Vec<(AuditorId, EncryptionPubKey)> = auditors_secret_vec
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
