//! The proofs library implements proof of different properties
//! of the plain text, given the cipher text without revealing the
//! plain text. For example proving that the value that was encrypted
//! is within a range.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use codec::{Decode, Encode, Error as CodecError, Input, Output};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    codec_wrapper::{
        CompressedRistrettoDecoder, CompressedRistrettoEncoder, RangeProofDencoder,
        RangeProofEncoder,
    },
    errors::Result,
};

const RANGE_PROOF_LABEL: &[u8] = b"PolymeshRangeProof";

// ------------------------------------------------------------------------
// Range Proof
// ------------------------------------------------------------------------

pub type RangeProofInitialMessage = CompressedRistretto;

pub type RangeProofFinalResponse = RangeProof;

/// Holds the non-interactive range proofs, equivalent of L_range of MERCAT paper.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InRangeProof {
    pub init: RangeProofInitialMessage,
    pub response: RangeProofFinalResponse,
    pub range: u32,
}

impl Encode for InRangeProof {
    fn size_hint(&self) -> usize {
        CompressedRistrettoEncoder(&self.init).size_hint()
            + RangeProofEncoder(&self.response).size_hint()
            + self.range.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        CompressedRistrettoEncoder(&self.init).encode_to(dest);
        RangeProofEncoder(&self.response).encode_to(dest);
        self.range.encode_to(dest);
    }
}

impl Decode for InRangeProof {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let init = <CompressedRistrettoDecoder>::decode(input)?.0;
        let response = <RangeProofDencoder>::decode(input)?.0;
        let range = <u32>::decode(input)?;

        Ok(InRangeProof {
            init,
            response,
            range,
        })
    }
}

impl InRangeProof {
    #[allow(dead_code)]
    pub fn build<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let range = 32;
        prove_within_range(0, Scalar::one(), range, rng).expect("This shouldn't happen.")
    }
}

/// Generate a range proof for a commitment to a secret value.
/// Range proof commitments are equevalant to the second term (Y)
/// of the Elgamal encryption.
pub fn prove_within_range<Rng: RngCore + CryptoRng>(
    secret_value: u64,
    rand_blind: Scalar,
    range: u32,
    rng: &mut Rng,
) -> Result<InRangeProof> {
    // Generators for Pedersen commitments.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    // Note that we are not supporting aggregating more than one value
    // from a single party into an aggretated proof yet.
    let bp_gens = BulletproofGens::new(64, 1);

    // Transcripts eliminate the need for a dealer by employing
    // the Fiat-Shamir huristic.
    let mut prover_transcript = Transcript::new(RANGE_PROOF_LABEL);

    let (proof, commitment) = RangeProof::prove_single_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &rand_blind,
        range as usize,
        rng,
    )?;

    Ok(InRangeProof {
        init: commitment,
        response: proof,
        range,
    })
}

/// Verify that a range proof is valid given a commitment to a secret value.
pub fn verify_within_range<Rng: RngCore + CryptoRng>(
    proof: &InRangeProof,
    rng: &mut Rng,
) -> Result<()> {
    // Generators for Pedersen commitments.
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

    // Transcripts eliminate the need for a dealer by employing
    // the Fiat-Shamir huristic.
    let mut verifier_transcript = Transcript::new(RANGE_PROOF_LABEL);

    Ok(proof
        .response
        .verify_single_with_rng(
            &bp_gens,
            &pc_gens,
            &mut verifier_transcript,
            &proof.init,
            proof.range as usize,
            rng,
        )?)
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

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let (witness, cipher) = elg_pub.encrypt_value(secret_value.into(), &mut rng);

        // Positive test: secret value within range [0, 2^32)
        let proof = prove_within_range(secret_value as u64, witness.blinding(), 32, &mut rng)
            .expect("This shouldn't happen.");
        assert_eq!(proof.range, 32);
        assert!(verify_within_range(&proof, &mut rng).is_ok());

        // Make sure the second part of the elgamal encryption is the same as the commited value in the range proof.
        assert_eq!(proof.init, cipher.y.compress());

        // Negative test: secret value outside the allowed range
        let large_secret_value: u64 = u64::from(u32::max_value()) + 3;
        let bad_proof =
            prove_within_range(large_secret_value, witness.blinding(), 32, &mut rng).unwrap();
        assert!(!verify_within_range(&bad_proof, &mut rng).is_ok());
    }
}
