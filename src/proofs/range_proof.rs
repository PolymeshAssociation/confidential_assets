//! The proofs library implements proof of different properties
//! of the plain text, given the cipher text without revealing the
//! plain text. For example proving that the value that was encrypted
//! is within a range.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::errors::Result;

const RANGE_PROOF_LABEL: &[u8] = b"PolymeshRangeProof";

// ------------------------------------------------------------------------
// Range Proof
// ------------------------------------------------------------------------

/// Holds the non-interactive range proofs, equivalent of L_range of MERCAT paper.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InRangeProof(pub RangeProof);

impl InRangeProof {
    #[allow(dead_code)]
    pub fn build<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let range = 32;
        Self::prove(0, Scalar::one(), range, rng).expect("This shouldn't happen.")
    }

    fn gens(len: usize) -> (PedersenGens, BulletproofGens) {
        // Generators for Pedersen commitments.
        let pc_gens = PedersenGens::default();

        // Generators for Bulletproofs, valid for proofs up to bitsize 64
        // and aggregation size up to `len`.
        let bp_gens = BulletproofGens::new(64, len);

        (pc_gens, bp_gens)
    }

    /// Generate a range proof for a commitment to a secret value.
    /// Range proof commitments are equevalant to the second term (Y)
    /// of the Elgamal encryption.
    pub fn prove<Rng: RngCore + CryptoRng>(
        secret_value: u64,
        blinding: Scalar,
        range: u32,
        rng: &mut Rng,
    ) -> Result<Self> {
        Self::prove_multiple(&[secret_value], &[blinding], range, rng)
    }

    /// Verify that a range proof is valid given a commitment to a secret value.
    pub fn verify<Rng: RngCore + CryptoRng>(
        &self,
        commitment: &CompressedRistretto,
        range: u32,
        rng: &mut Rng,
    ) -> Result<()> {
        self.verify_multiple(&[*commitment], range, rng)
    }

    /// Generate a range proof for multiple secret values.
    /// Range proof commitments are equevalant to the second term (Y)
    /// of the Elgamal encryption.
    pub fn prove_multiple<Rng: RngCore + CryptoRng>(
        values: &[u64],
        blindings: &[Scalar],
        range: u32,
        rng: &mut Rng,
    ) -> Result<Self> {
        // Get generators.
        let (pc_gens, bp_gens) = Self::gens(values.len());

        // Transcripts eliminate the need for a dealer by employing
        // the Fiat-Shamir huristic.
        let mut prover_transcript = Transcript::new(RANGE_PROOF_LABEL);

        let (proof, _commitments) = RangeProof::prove_multiple_with_rng(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            values,
            blindings,
            range as usize,
            rng,
        )?;

        Ok(Self(proof))
    }

    /// Verify that a range proof is valid given multiple commitments to secret values.
    pub fn verify_multiple<Rng: RngCore + CryptoRng>(
        &self,
        commitments: &[CompressedRistretto],
        range: u32,
        rng: &mut Rng,
    ) -> Result<()> {
        // Get generators.
        let (pc_gens, bp_gens) = Self::gens(commitments.len());

        // Transcripts eliminate the need for a dealer by employing
        // the Fiat-Shamir huristic.
        let mut verifier_transcript = Transcript::new(RANGE_PROOF_LABEL);

        Ok(self.0.verify_multiple_with_rng(
            &bp_gens,
            &pc_gens,
            &mut verifier_transcript,
            commitments,
            range as usize,
            rng,
        )?)
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::elgamal::ElgamalSecretKey;
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn basic_range_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 42u32;
        let range = 32;

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let (witness, cipher) = elg_pub.encrypt_value(secret_value.into(), &mut rng);

        // Positive test: secret value within range [0, 2^32)
        let proof = InRangeProof::prove(secret_value as u64, witness.blinding(), range, &mut rng)
            .expect("This shouldn't happen.");
        assert!(proof.verify(&cipher.y.compress(), range, &mut rng).is_ok());

        // Negative test: secret value outside the allowed range
        let large_secret_value: u64 = u64::from(u32::max_value()) + 3;
        let (bad_witness, bad_cipher) = elg_pub.encrypt_value(large_secret_value.into(), &mut rng);
        let bad_proof =
            InRangeProof::prove(large_secret_value, bad_witness.blinding(), range, &mut rng).unwrap();
        assert!(!bad_proof.verify(&bad_cipher.y.compress(), range, &mut rng).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn basic_two_range_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value1 = 42u64;
        let secret_value2 = 1234u64;
        let range = 32;

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let (witness1, cipher1) = elg_pub.encrypt_value(secret_value1.into(), &mut rng);
        let (witness2, cipher2) = elg_pub.encrypt_value(secret_value2.into(), &mut rng);

        // Positive test: secret values within range [0, 2^32)
        let proof = InRangeProof::prove_multiple(&[secret_value1, secret_value2], &[witness1.blinding(), witness2.blinding()], range, &mut rng)
            .expect("This shouldn't happen.");
        assert!(proof.verify_multiple(&[
            cipher1.y.compress(),
            cipher2.y.compress()
        ], range, &mut rng).is_ok());

        // Negative test: secret value outside the allowed range
        let large_secret_value: u64 = u64::from(u32::max_value()) + 3;
        let (bad_witness, bad_cipher) = elg_pub.encrypt_value(large_secret_value.into(), &mut rng);
        let bad_proof = InRangeProof::prove_multiple(&[large_secret_value, secret_value2], &[bad_witness.blinding(), witness2.blinding()], range, &mut rng)
            .expect("This shouldn't happen.");
        assert!(!bad_proof.verify_multiple(&[
            bad_cipher.y.compress(),
            cipher2.y.compress()
        ], range, &mut rng).is_ok());
    }
}
