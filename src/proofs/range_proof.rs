//! The proofs library implements proof of different properties
//! of the plain text, given the cipher text without revealing the
//! plain text. For example proving that the value that was encrypted
//! is within a range.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use crate::errors::Result;

const RANGE_PROOF_LABEL: &[u8] = b"PolymeshRangeProof";

// ------------------------------------------------------------------------
// Range Proof
// ------------------------------------------------------------------------

/// Holds the non-interactive range proofs, equivalent of L_range of MERCAT paper.
#[derive(Clone, Debug)]
pub struct InRangeProof(pub RangeProof);

impl InRangeProof {
    #[allow(dead_code)]
    pub fn build<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let pc_gens = PedersenGens::default();
        let range = 32;
        Self::prove(&pc_gens, 0, Scalar::one(), range, rng).expect("This shouldn't happen.")
    }

    fn bp_gens(len: usize) -> BulletproofGens {
        // Generators for Bulletproofs, valid for proofs up to bitsize 64
        // and aggregation size up to `len`.
        BulletproofGens::new(64, len)
    }

    /// Generate a range proof for a commitment to a secret value.
    /// Range proof commitments are equevalant to the second term (Y)
    /// of the Elgamal encryption.
    pub fn prove<Rng: RngCore + CryptoRng>(
        pc_gens: &PedersenGens,
        secret_value: u64,
        blinding: Scalar,
        range: u32,
        rng: &mut Rng,
    ) -> Result<Self> {
        let mut transcript = Transcript::new(RANGE_PROOF_LABEL);
        Self::prove_multiple(
            pc_gens,
            &mut transcript,
            &[secret_value],
            &[blinding],
            range,
            rng,
        )
    }

    /// Verify that a range proof is valid given a commitment to a secret value.
    pub fn verify<Rng: RngCore + CryptoRng>(
        &self,
        pc_gens: &PedersenGens,
        commitment: &CompressedRistretto,
        range: u32,
        rng: &mut Rng,
    ) -> Result<()> {
        let mut transcript = Transcript::new(RANGE_PROOF_LABEL);
        self.verify_multiple(pc_gens, &mut transcript, &[*commitment], range, rng)
    }

    /// Generate a range proof for multiple secret values.
    /// Range proof commitments are equevalant to the second term (Y)
    /// of the Elgamal encryption.
    pub fn prove_multiple<Rng: RngCore + CryptoRng>(
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        values: &[u64],
        blindings: &[Scalar],
        range: u32,
        rng: &mut Rng,
    ) -> Result<Self> {
        // Get bp generators.
        let bp_gens = Self::bp_gens(values.len());

        let (proof, _commitments) = RangeProof::prove_multiple_with_rng(
            &bp_gens,
            pc_gens,
            transcript,
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
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        commitments: &[CompressedRistretto],
        range: u32,
        rng: &mut Rng,
    ) -> Result<()> {
        // Get bp generators.
        let bp_gens = Self::bp_gens(commitments.len());

        Ok(self.0.verify_multiple_with_rng(
            &bp_gens,
            pc_gens,
            transcript,
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

        let pc_gens = PedersenGens::default();
        // Positive test: secret value within range [0, 2^32)
        let proof = InRangeProof::prove(
            &pc_gens,
            secret_value as u64,
            witness.blinding(),
            range,
            &mut rng,
        )
        .expect("This shouldn't happen.");
        assert!(proof
            .verify(&pc_gens, &cipher.y.compress(), range, &mut rng)
            .is_ok());

        // Negative test: secret value outside the allowed range
        let large_secret_value: u64 = u64::from(u32::max_value()) + 3;
        let (bad_witness, bad_cipher) = elg_pub.encrypt_value(large_secret_value.into(), &mut rng);
        let bad_proof = InRangeProof::prove(
            &pc_gens,
            large_secret_value,
            bad_witness.blinding(),
            range,
            &mut rng,
        )
        .unwrap();
        assert!(!bad_proof
            .verify(&pc_gens, &bad_cipher.y.compress(), range, &mut rng)
            .is_ok());
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

        let pc_gens = PedersenGens::default();
        // Positive test: secret values within range [0, 2^32)
        let mut prover_transcript = Transcript::new(RANGE_PROOF_LABEL);
        let proof = InRangeProof::prove_multiple(
            &pc_gens,
            &mut prover_transcript,
            &[secret_value1, secret_value2],
            &[witness1.blinding(), witness2.blinding()],
            range,
            &mut rng,
        )
        .expect("This shouldn't happen.");
        let mut verify_transcript = Transcript::new(RANGE_PROOF_LABEL);
        assert!(proof
            .verify_multiple(
                &pc_gens,
                &mut verify_transcript,
                &[cipher1.y.compress(), cipher2.y.compress()],
                range,
                &mut rng
            )
            .is_ok());

        // Negative test: secret value outside the allowed range
        let large_secret_value: u64 = u64::from(u32::max_value()) + 3;
        let (bad_witness, bad_cipher) = elg_pub.encrypt_value(large_secret_value.into(), &mut rng);
        let mut prover_transcript = Transcript::new(RANGE_PROOF_LABEL);
        let bad_proof = InRangeProof::prove_multiple(
            &pc_gens,
            &mut prover_transcript,
            &[large_secret_value, secret_value2],
            &[bad_witness.blinding(), witness2.blinding()],
            range,
            &mut rng,
        )
        .expect("This shouldn't happen.");
        let mut verify_transcript = Transcript::new(RANGE_PROOF_LABEL);
        assert!(!bad_proof
            .verify_multiple(
                &pc_gens,
                &mut verify_transcript,
                &[bad_cipher.y.compress(), cipher2.y.compress()],
                range,
                &mut rng
            )
            .is_ok());
    }
}
