use crate::{
    elgamal::{CipherText, ElgamalPublicKey},
    errors::{Error, Result},
    proofs::{
        bulletproofs::PedersenGens,
        ciphertext_refreshment_proof::{
            CipherEqualSamePubKeyProof, CipherTextRefreshmentProverAwaitingChallenge,
            CipherTextRefreshmentVerifier,
        },
        encryption_proofs::single_property_prover_with_transcript,
        encryption_proofs::single_property_verifier_with_transcript,
        range_proof::InRangeProof,
    },
    Balance, ElgamalKeys, Scalar, BALANCE_RANGE,
};

use rand_core::{CryptoRng, RngCore};

#[cfg(not(feature = "std"))]
use alloc::{self as std, vec::Vec};
use codec::{Decode, Encode};
use merlin::Transcript;
use scale_info::TypeInfo;

/// The domain label for the Confidential Burn proofs.
pub const CONFIDENTIAL_BURN_PROOF_LABEL: &[u8] = b"PolymeshConfidentialBurnProof";

/// The confidential burn proof created by the asset issuer.
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub struct ConfidentialBurnProof {
    // SCALE encoded inner proof.
    pub(crate) encoded_inner_proof: Vec<u8>,
}

impl ConfidentialBurnProof {
    /// Create a confidential asset burn proof.
    pub fn new<T: RngCore + CryptoRng>(
        issuer_account: &ElgamalKeys,
        issuer_init_balance: &CipherText,
        issuer_balance: Balance,
        amount: Balance,
        rng: &mut T,
    ) -> Result<Self> {
        let mut transcript = Transcript::new(CONFIDENTIAL_BURN_PROOF_LABEL);
        // Ensure the issuer has enough funds.
        ensure!(
            issuer_balance >= amount,
            Error::NotEnoughFund {
                balance: issuer_balance,
                transaction_amount: amount
            }
        );
        // Verify the issuer's balance.
        issuer_account.verify(issuer_init_balance, &issuer_balance.into())?;

        // Prove that the amount encrypted under different public keys are the same.
        let gens = PedersenGens::default();

        // Refresh the encrypted balance and prove that the refreshment was done
        // correctly.
        let balance_refresh_enc_blinding = Scalar::random(rng);
        let refreshed_enc_balance = issuer_init_balance.refresh_with_hint(
            &issuer_account.secret,
            balance_refresh_enc_blinding,
            &issuer_balance.into(),
        )?;

        let balance_refreshed_same_proof = single_property_prover_with_transcript(
            &mut transcript,
            CipherTextRefreshmentProverAwaitingChallenge::new(
                issuer_account.secret.clone(),
                issuer_account.public.clone(),
                *issuer_init_balance,
                refreshed_enc_balance,
                &gens,
            ),
            rng,
        )?;

        // prove that the issuer has enough funds.
        let range_proofs = InRangeProof::prove_multiple(
            &gens,
            &mut transcript,
            &[(issuer_balance - amount).into()],
            &[balance_refresh_enc_blinding],
            BALANCE_RANGE,
            rng,
        )?;

        let inner = ConfidentialBurnInnerProof {
            range_proofs,
            balance_refreshed_same_proof,
            refreshed_enc_balance,
        };
        Ok(Self {
            encoded_inner_proof: inner.encode(),
        })
    }

    /// Verify the ZK-proofs using only public information.
    pub fn verify<R: RngCore + CryptoRng>(
        &self,
        issuer_account: &ElgamalPublicKey,
        issuer_init_balance: &CipherText,
        amount: Balance,
        rng: &mut R,
    ) -> Result<CipherText> {
        let mut transcript = Transcript::new(CONFIDENTIAL_BURN_PROOF_LABEL);
        let gens = PedersenGens::default();

        // Decode the inner proof.
        let inner = self.inner_proof()?;

        // verify that the balance refreshment was done correctly.
        single_property_verifier_with_transcript(
            &mut transcript,
            &CipherTextRefreshmentVerifier::new(
                *issuer_account,
                *issuer_init_balance,
                inner.refreshed_enc_balance,
                &gens,
            ),
            &inner.balance_refreshed_same_proof,
        )?;

        // verify that the balance has enough fund.
        let enc_amount = CipherText::value(amount.into());
        let updated_balance = inner.refreshed_enc_balance - enc_amount;
        let updated_balance_commitment = updated_balance.y.compress();
        inner.range_proofs.verify_multiple(
            &gens,
            &mut transcript,
            &[updated_balance_commitment],
            BALANCE_RANGE,
            rng,
        )?;

        Ok(enc_amount)
    }

    pub fn inner_proof(&self) -> Result<ConfidentialBurnInnerProof> {
        Ok(ConfidentialBurnInnerProof::decode(
            &mut self.encoded_inner_proof.as_slice(),
        )?)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.encoded_inner_proof.clone()
    }

    pub fn from_bytes(proof: &Vec<u8>) -> Result<Self> {
        Ok(Self {
            encoded_inner_proof: proof.clone(),
        })
    }
}

/// Holds the zk-proofs of the confidential burn transaction.
#[derive(Clone, Encode, Decode, Debug)]
pub struct ConfidentialBurnInnerProof {
    /// The issuer's balance re-encrypted using a new blinding.
    ///
    /// This encrypted value is needed for the "Enough funds" range proof, because the
    /// blinding value needs to be known and we don't want the users to have to keep
    /// an updated copy of the blinding value.
    pub refreshed_enc_balance: CipherText,
    /// ZK-proof that `refreshed_enc_balance` encrypts the same value as the issuer's balance.
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    /// Bulletproof range proof for "Enough funds".
    pub range_proofs: InRangeProof,
}

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
        key: ElgamalPublicKey,
        balance: Balance,
        rng: &mut R,
    ) -> Result<CipherText> {
        let (_, enc_balance) = key.encrypt_value(Scalar::from(balance), rng);

        Ok(enc_balance)
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_burn_success() {
        let issuer_balance = 40;
        let burn_amount = 30;

        let mut rng = StdRng::from_seed([17u8; 32]);

        let issuer_account = mock_gen_enc_key_pair(10u8);

        let issuer_init_balance =
            mock_gen_account(issuer_account.public, issuer_balance, &mut rng).unwrap();

        // Create the burn proof check its result and state
        let proof = ConfidentialBurnProof::new(
            &issuer_account,
            &issuer_init_balance,
            issuer_balance,
            burn_amount,
            &mut rng,
        )
        .expect("Burn proof");

        assert!(proof
            .verify(
                &issuer_account.public,
                &issuer_init_balance,
                burn_amount,
                &mut rng,
            )
            .is_ok());
    }
}
