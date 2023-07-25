use crate::{
    elgamal::CommitmentWitness,
    errors::Fallible,
    proofs::{
        bulletproofs::PedersenGens,
        correctness_proof::{CorrectnessProverAwaitingChallenge, CorrectnessVerifier},
        encryption_proofs::single_property_prover,
        encryption_proofs::single_property_verifier,
    },
    AccountCreatorInitializer, AccountCreatorVerifier, Balance, EncryptedAmount, PubAccount,
    PubAccountTx, Scalar, SecAccount,
};
use rand_core::{CryptoRng, RngCore};

// ------------------------------------------------------------------------------------------------
// -                                        Any User                                              -
// ------------------------------------------------------------------------------------------------

pub struct AccountCreator;

impl AccountCreatorInitializer for AccountCreator {
    fn create<T: RngCore + CryptoRng>(
        &self,
        secret: &SecAccount,
        rng: &mut T,
    ) -> Fallible<PubAccountTx> {
        let balance_blinding = Scalar::random(rng);
        let gens = &PedersenGens::default();

        // Encrypt the balance and prove that the encrypted balance is correct
        let balance: Balance = 0;
        let balance_witness = CommitmentWitness::new(balance.into(), balance_blinding);
        let initial_balance = secret.enc_keys.public.encrypt(&balance_witness);

        let initial_balance_correctness_proof = single_property_prover(
            CorrectnessProverAwaitingChallenge {
                pub_key: secret.enc_keys.public,
                w: balance_witness,
                pc_gens: &gens,
            },
            rng,
        )?;

        Ok(PubAccountTx {
            pub_account: PubAccount {
                owner_enc_pub_key: secret.enc_keys.public,
            },
            initial_balance,
            initial_balance_correctness_proof,
        })
    }
}

pub fn deposit(initial_balance: &EncryptedAmount, enc_amount: &EncryptedAmount) -> EncryptedAmount {
    initial_balance + enc_amount
}

pub fn withdraw(
    initial_balance: &EncryptedAmount,
    enc_amount: &EncryptedAmount,
) -> EncryptedAmount {
    initial_balance - enc_amount
}

// ------------------------------------------------------------------------------------------------
// -                                          Validator                                           -
// ------------------------------------------------------------------------------------------------

pub struct AccountValidator;

impl AccountCreatorVerifier for AccountValidator {
    fn verify(&self, account: &PubAccountTx) -> Fallible<()> {
        let gens = &PedersenGens::default();

        // Verify that the encrypted balance is correct
        let balance: Balance = 0;
        single_property_verifier(
            &CorrectnessVerifier {
                value: balance.into(),
                pub_key: account.pub_account.owner_enc_pub_key,
                cipher: account.initial_balance,
                pc_gens: &gens,
            },
            account.initial_balance_correctness_proof,
        )?;

        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------
// -                                            Tests                                             -
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{elgamal::ElgamalSecretKey, EncryptionKeys, Scalar};
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    #[test]
    #[wasm_bindgen_test]
    fn test_account_creation_and_validation() {
        // ----------------------- setup
        let mut rng = StdRng::from_seed([10u8; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let enc_keys = EncryptionKeys {
            public: elg_pub,
            secret: elg_secret,
        };
        let secret_account = SecAccount { enc_keys };

        // ----------------------- test
        let account_creator = AccountCreator;
        let sender_account_tx = account_creator.create(&secret_account, &mut rng).unwrap();

        let decrypted_balance = secret_account
            .enc_keys
            .secret
            .decrypt(&sender_account_tx.initial_balance)
            .unwrap();
        assert_eq!(decrypted_balance, 0);

        let account_vldtr = AccountValidator;
        let result = account_vldtr.verify(&sender_account_tx);
        result.unwrap();
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_account_updates() {
        // ----------------------- setup
        let mut rng = StdRng::from_seed([10u8; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let enc_keys = EncryptionKeys {
            public: elg_pub,
            secret: elg_secret,
        };
        let secret_account = SecAccount { enc_keys };

        // ----------------------- test
        let account_creator = AccountCreator;
        let pub_account_tx = account_creator.create(&secret_account, &mut rng).unwrap();

        let balance = secret_account
            .enc_keys
            .secret
            .decrypt(&pub_account_tx.initial_balance)
            .unwrap();
        assert_eq!(balance, 0);

        let ten: Balance = 10;
        let ten = secret_account
            .enc_keys
            .public
            .encrypt_value(ten.into(), &mut rng)
            .1;
        let five: Balance = 5;
        let five = secret_account
            .enc_keys
            .public
            .encrypt_value(five.into(), &mut rng)
            .1;

        let new_enc_balance = deposit(&pub_account_tx.initial_balance, &ten);
        let balance = secret_account
            .enc_keys
            .secret
            .decrypt(&new_enc_balance)
            .unwrap();
        assert_eq!(balance, 10);

        let new_enc_balance = withdraw(&new_enc_balance, &five);
        let balance = secret_account
            .enc_keys
            .secret
            .decrypt(&new_enc_balance)
            .unwrap();
        assert_eq!(balance, 5);
    }
}
