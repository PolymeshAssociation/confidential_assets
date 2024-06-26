//! The proof of correct encryption of the given value.
//! For more details see section 5.2 of the whitepaper.

use crate::{
    codec_wrapper::{WrappedCompressedRistretto, WrappedScalar},
    elgamal::{CipherText, CommitmentWitness, ElgamalPublicKey},
    errors::{Error, Result},
    proofs::{
        encryption_proofs::{
            ProofProver, ProofProverAwaitingChallenge, ProofVerifier, ZKPChallenge, ZKProofResponse,
        },
        transcript::{TranscriptProtocol, UpdateTranscript},
    },
};
use bulletproofs::PedersenGens;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use codec::{Decode, Encode};
use core::convert::From;

/// The domain label for the correctness proof.
pub const CORRECTNESS_PROOF_LABEL: &[u8] = b"PolymeshCorrectnessProof";
/// The domain label for the challenge.
pub const CORRECTNESS_PROOF_CHALLENGE_LABEL: &[u8] = b"PolymeshCorrectnessFinalResponseChallenge";

// ------------------------------------------------------------------------
// Proof of Correct Encryption of the Given Value
// ------------------------------------------------------------------------

#[derive(PartialEq, Copy, Clone, Encode, Decode, Debug, Default)]
pub struct CorrectnessFinalResponse(WrappedScalar);

impl From<Scalar> for CorrectnessFinalResponse {
    fn from(response: Scalar) -> Self {
        CorrectnessFinalResponse(response.into())
    }
}

#[derive(PartialEq, Copy, Clone, Encode, Decode, Debug)]
pub struct CorrectnessInitialMessage {
    pub a: WrappedCompressedRistretto,
    pub b: WrappedCompressedRistretto,
}

/// A default implementation used for testing.
impl Default for CorrectnessInitialMessage {
    fn default() -> Self {
        CorrectnessInitialMessage {
            a: RISTRETTO_BASEPOINT_POINT.into(),
            b: RISTRETTO_BASEPOINT_POINT.into(),
        }
    }
}

impl UpdateTranscript for CorrectnessInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<ZKPChallenge> {
        transcript.append_validated_point(b"A", &self.a.compress())?;
        transcript.append_validated_point(b"B", &self.b.compress())?;
        transcript.scalar_challenge(CORRECTNESS_PROOF_CHALLENGE_LABEL)
    }
}

fn start_transcript(transcript: &mut Transcript, pub_key: &ElgamalPublicKey) -> Result<()> {
    transcript.append_domain_separator(CORRECTNESS_PROOF_LABEL);
    transcript.append_validated_point(b"PK", &pub_key.pub_key.compress())?;
    Ok(())
}

/// Holds the non-interactive proofs of correctness, equivalent of L_correct of MERCAT paper.
pub type CorrectnessProof = ZKProofResponse<CorrectnessInitialMessage, CorrectnessFinalResponse>;

pub struct CorrectnessProverAwaitingChallenge<'a> {
    /// The public key used for the elgamal encryption.
    pub pub_key: ElgamalPublicKey,

    /// The secret commitment witness.
    pub w: CommitmentWitness,

    /// Pedersen Generators
    pub pc_gens: &'a PedersenGens,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CorrectnessProver {
    /// The secret commitment witness.
    w: CommitmentWitness,

    /// The randomness generate in the first round.
    u: Scalar,
}

impl<'a> ProofProverAwaitingChallenge for CorrectnessProverAwaitingChallenge<'a> {
    type ZKInitialMessage = CorrectnessInitialMessage;
    type ZKFinalResponse = CorrectnessFinalResponse;
    type ZKProver = CorrectnessProver;

    fn start_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        start_transcript(transcript, &self.pub_key)
    }

    fn create_transcript_rng<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        transcript: &Transcript,
    ) -> TranscriptRng {
        transcript.create_transcript_rng_from_witness(rng, &self.w)
    }

    fn generate_initial_message(
        &self,
        rng: &mut TranscriptRng,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let rand_commitment = Scalar::random(rng);

        (
            CorrectnessProver {
                w: self.w.clone(),
                u: rand_commitment,
            },
            CorrectnessInitialMessage {
                a: (rand_commitment * *self.pub_key.pub_key).into(),
                b: (rand_commitment * self.pc_gens.B_blinding).into(),
            },
        )
    }
}

impl ProofProver<CorrectnessFinalResponse> for CorrectnessProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> CorrectnessFinalResponse {
        CorrectnessFinalResponse((self.u + c.x() * self.w.blinding()).into())
    }
}

pub struct CorrectnessVerifier<'a> {
    /// The encrypted value (aka the plain text).
    pub value: Scalar,

    /// The public key to which the `value` is encrypted.
    pub pub_key: ElgamalPublicKey,

    /// The encryption cipher text.
    pub cipher: CipherText,

    /// The Generator Points
    pub pc_gens: &'a PedersenGens,
}

impl<'a> ProofVerifier for CorrectnessVerifier<'a> {
    type ZKInitialMessage = CorrectnessInitialMessage;
    type ZKFinalResponse = CorrectnessFinalResponse;

    fn start_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        start_transcript(transcript, &self.pub_key)
    }

    fn verify(
        &self,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        z: &Self::ZKFinalResponse,
    ) -> Result<()> {
        let z = *z.0;
        let a = initial_message.a.decompress();
        let b = initial_message.b.decompress();
        let generators = self.pc_gens;
        let y_prime = *self.cipher.y - (self.value * generators.B);

        ensure!(
            z * *self.pub_key.pub_key == a + challenge.x() * *self.cipher.x,
            Error::CorrectnessFinalResponseVerificationError { check: 1 }
        );
        ensure!(
            z * generators.B_blinding == b + challenge.x() * y_prime,
            Error::CorrectnessFinalResponseVerificationError { check: 2 }
        );
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
    use crate::{elgamal::ElgamalSecretKey, proofs::*};
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [17u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn test_correctness_proof() {
        let gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 13u32;

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let (w, cipher) = elg_pub.encrypt_value(secret_value.into(), &mut rng);

        let prover = CorrectnessProverAwaitingChallenge {
            pub_key: elg_pub,
            w,
            pc_gens: &gens,
        };
        let verifier = CorrectnessVerifier {
            value: Scalar::from(secret_value),
            pub_key: elg_pub,
            cipher,
            pc_gens: &gens,
        };
        let mut transcript = Transcript::new(CORRECTNESS_PROOF_LABEL);

        // Positive tests
        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &transcript);
        let (prover, initial_message) = prover.generate_initial_message(&mut transcript_rng);
        let challenge = initial_message.update_transcript(&mut transcript).unwrap();
        let final_response = prover.apply_challenge(&challenge);

        let result = verifier.verify(&challenge, &initial_message, &final_response);
        assert!(result.is_ok());

        // Negative tests
        let bad_initial_message = CorrectnessInitialMessage::default();
        let result = verifier.verify(&challenge, &bad_initial_message, &final_response);
        assert_err!(
            result,
            Error::CorrectnessFinalResponseVerificationError { check: 1 }
        );

        let bad_final_response = CorrectnessFinalResponse::default();
        let result = verifier.verify(&challenge, &initial_message, &bad_final_response);
        assert_err!(
            result,
            Error::CorrectnessFinalResponseVerificationError { check: 1 }
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn serialize_deserialize_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 42u32;
        let secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pub_key = secret_key.get_public_key();
        let rand_blind = Scalar::random(&mut rng);
        let w = CommitmentWitness::new(secret_value.into(), rand_blind);
        let gens = PedersenGens::default();
        let prover = CorrectnessProverAwaitingChallenge {
            pub_key,
            w,
            pc_gens: &gens,
        };
        let (initial_message, final_response) = encryption_proofs::single_property_prover::<
            StdRng,
            CorrectnessProverAwaitingChallenge,
        >(prover, &mut rng)
        .unwrap();

        let bytes = initial_message.encode();
        let mut input = bytes.as_slice();
        let recovered_initial_message = <CorrectnessInitialMessage>::decode(&mut input).unwrap();
        assert_eq!(recovered_initial_message, initial_message);

        let bytes = final_response.encode();
        let mut input = bytes.as_slice();
        let recovered_final_response = <CorrectnessFinalResponse>::decode(&mut input).unwrap();
        assert_eq!(recovered_final_response, final_response);
    }
}
