//! Encryption proofs' interface definitions and
//! Non-Interactive Zero Knowledge Proof API.

use curve25519_dalek::scalar::Scalar;
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};
use sp_std::convert::TryFrom;

use crate::errors::{Error, Result};
use crate::proofs::transcript::{TranscriptProtocol, UpdateTranscript};

/// The domain label for the encryption proofs.
pub const ENCRYPTION_PROOFS_LABEL: &[u8] = b"PolymeshEncryptionProofs";
/// The domain label for the challenge.
pub const ENCRYPTION_PROOFS_CHALLENGE_LABEL: &[u8] = b"PolymeshEncryptionProofsChallenge";

// ------------------------------------------------------------------------
// Sigma Protocol's Prover and Verifier Interfaces
// ------------------------------------------------------------------------

/// A scalar challenge.
pub struct ZKPChallenge {
    x: Scalar,
}

impl ZKPChallenge {
    pub fn x(&self) -> &Scalar {
        &self.x
    }
}

impl TryFrom<Scalar> for ZKPChallenge {
    type Error = Error;

    fn try_from(x: Scalar) -> Result<Self, Self::Error> {
        ensure!(x != Scalar::zero(), Error::VerificationError);
        Ok(ZKPChallenge { x })
    }
}

/// The interface for a 3-Sigma protocol.
/// Abstracting the prover and verifier roles.
///
/// Each proof needs to use the same `ZKInitialMessage` and `ZKFinalResponse` types
/// between the prover and the verifier.
/// Each `ZKInitialMessage` needs to implement the `UpdateTranscript` trait.
pub trait ProofProverAwaitingChallenge {
    type ZKInitialMessage: UpdateTranscript;
    type ZKFinalResponse;
    type ZKProver: ProofProver<Self::ZKFinalResponse>;

    /// Create an RNG from current transcript's state and an RNG.
    /// This new RNG will be used by the prover to generate randomness
    /// in the first round of the Sigma protocol.
    ///
    /// Note: provers must not share a single instance of a transcript RNG.
    /// Every prover must create a fresh RNG and seed it with its given secret.
    /// For more details see Merlin's documentation:
    /// <https://doc.dalek.rs/merlin/struct.TranscriptRngBuilder.html>
    ///
    /// # Inputs
    /// `rng` An external RNG.
    /// `transcript` A Merlin transcript.
    ///
    /// # Output
    /// A transcript RNG.
    fn create_transcript_rng<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        transcript: &Transcript,
    ) -> TranscriptRng;

    /// First round of the Sigma protocol. Prover generates an initial message.
    ///
    /// # Inputs
    /// `pc_gens` The Pedersen Generators used for the Elgamal encryption.
    /// `rng`     An RNG created by calling `create_transcript_rng()`.
    ///
    /// # Output
    /// A initial message.
    fn generate_initial_message(
        &self,
        rng: &mut TranscriptRng,
    ) -> (Self::ZKProver, Self::ZKInitialMessage);
}

pub trait ProofProver<ZKFinalResponse> {
    /// Third round of the Sigma protocol. Prover receives a challenge and
    /// uses it to generate the final response.
    ///
    /// # Inputs
    /// `challenge` The scalar challenge, generated by the transcript.
    ///
    /// # Output
    /// A final response.
    fn apply_challenge(&self, challenge: &ZKPChallenge) -> ZKFinalResponse;
}

pub trait ProofVerifier {
    type ZKInitialMessage: UpdateTranscript;
    type ZKFinalResponse;

    /// Forth round of the Sigma protocol. Verifier receives the initial message
    /// and the final response, and verifies them.
    ///
    /// # Inputs
    /// `pc_gens`         The Pedersen Generators used for the Elgamal encryption.
    /// `challenge`       The scalar challenge, generated by the transcript.
    /// `initial_message` The initial message, generated by the Prover.
    /// `final_response`  The final response, generated by the Prover.
    ///
    /// # Output
    /// Ok on success, or an error on failure.
    fn verify(
        &self,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        final_response: &Self::ZKFinalResponse,
    ) -> Result<()>;
}

// ------------------------------------------------------------------------
// Non-Interactive Zero Knowledge Proofs API
// ------------------------------------------------------------------------

/// The proof in the non-interactive implementation of the protocol is a tuple
/// of the initial message and the final response.
pub type ZKProofResponse<ZKInitialMessage, ZKFinalResponse> = (ZKInitialMessage, ZKFinalResponse);

/// The non-interactive implementation of the protocol for a single
/// encryption proof's prover role.
///
/// # Inputs
/// `prover` Any prover that implements the `ProofProver` trait.
/// `rng`    An RNG.
///
/// # Outputs
/// An initial message and a final response as a tuple on success, or failure on an error.
pub fn single_property_prover<
    T: RngCore + CryptoRng,
    ProverAwaitingChallenge: ProofProverAwaitingChallenge,
>(
    prover_ac: ProverAwaitingChallenge,
    rng: &mut T,
) -> Result<
    ZKProofResponse<
        ProverAwaitingChallenge::ZKInitialMessage,
        ProverAwaitingChallenge::ZKFinalResponse,
    >,
> {
    let mut transcript = Transcript::new(ENCRYPTION_PROOFS_LABEL);

    let mut transcript_rng = prover_ac.create_transcript_rng(rng, &transcript);
    let (prover, initial_message) = prover_ac.generate_initial_message(&mut transcript_rng);

    // Update the transcript with Prover's initial message
    initial_message.update_transcript(&mut transcript)?;
    let challenge = transcript.scalar_challenge(ENCRYPTION_PROOFS_CHALLENGE_LABEL)?;

    let final_response = prover.apply_challenge(&challenge);

    Ok((initial_message, final_response))
}

/// The non-interactive implementation of the protocol for a single
/// encryption proof's verifier role.
///
/// # Inputs
/// `verifier` Any verifier that implements the `ProofVerifier` trait.
/// `proof`    Prover's initial message and final response.
///
/// # Outputs
/// Ok on success, or failure on error.
pub fn single_property_verifier<Verifier: ProofVerifier>(
    verifier: &Verifier,
    proof: ZKProofResponse<Verifier::ZKInitialMessage, Verifier::ZKFinalResponse>,
) -> Result<()> {
    let initial_message = proof.0;
    let final_response = proof.1;
    let mut transcript = Transcript::new(ENCRYPTION_PROOFS_LABEL);

    // Update the transcript with Prover's initial message
    initial_message.update_transcript(&mut transcript)?;
    let challenge = transcript.scalar_challenge(ENCRYPTION_PROOFS_CHALLENGE_LABEL)?;

    verifier.verify(&challenge, &initial_message, &final_response)?;

    Ok(())
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{
        elgamal::{CipherText, CommitmentWitness, ElgamalPublicKey, ElgamalSecretKey},
        errors::Error,
        proofs::{
            correctness_proof::{
                CorrectnessFinalResponse, CorrectnessInitialMessage,
                CorrectnessProverAwaitingChallenge, CorrectnessVerifier,
            },
            wellformedness_proof::{WellformednessProverAwaitingChallenge, WellformednessVerifier},
        },
    };
    use bulletproofs::PedersenGens;
    use rand::{rngs::StdRng, SeedableRng};
    use sp_std::convert::TryFrom;
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];
    const SEED_2: [u8; 32] = [7u8; 32];

    fn create_correctness_proof_objects_helper<'a>(
        witness: CommitmentWitness,
        pub_key: ElgamalPublicKey,
        cipher: CipherText,
        pc_gens: &'a PedersenGens,
    ) -> (
        CorrectnessProverAwaitingChallenge<'a>,
        CorrectnessVerifier<'a>,
    ) {
        let prover = CorrectnessProverAwaitingChallenge {
            pub_key,
            w: witness.clone(),
            pc_gens,
        };
        let verifier = CorrectnessVerifier {
            value: witness.value(),
            pub_key,
            cipher,
            pc_gens,
        };

        (prover, verifier)
    }

    fn create_wellformedness_proof_objects_helper<'a>(
        witness: CommitmentWitness,
        pub_key: ElgamalPublicKey,
        cipher: CipherText,
        pc_gens: &'a PedersenGens,
    ) -> (
        WellformednessProverAwaitingChallenge,
        WellformednessVerifier,
    ) {
        let prover = WellformednessProverAwaitingChallenge {
            pub_key,
            w: witness,
            pc_gens,
        };
        let verifier = WellformednessVerifier {
            pub_key,
            cipher,
            pc_gens,
        };

        (prover, verifier)
    }

    #[test]
    #[wasm_bindgen_test]
    fn nizkp_proofs() {
        let mut rng = StdRng::from_seed(SEED_1);
        let gens = PedersenGens::default();

        let secret_value = 42u32;
        let secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pub_key = secret_key.get_public_key();
        let (w, cipher) = pub_key.encrypt_value(secret_value.into(), &mut rng);

        let (prover0, verifier0) =
            create_correctness_proof_objects_helper(w.clone(), pub_key, cipher, &gens);
        let (initial_message0, final_response0) =
            single_property_prover::<StdRng, CorrectnessProverAwaitingChallenge>(prover0, &mut rng)
                .unwrap();

        let (prover1, verifier1) =
            create_wellformedness_proof_objects_helper(w, pub_key, cipher, &gens);
        let (initial_message1, final_response1) = single_property_prover::<
            StdRng,
            WellformednessProverAwaitingChallenge,
        >(prover1, &mut rng)
        .unwrap();

        // Positive tests
        assert!(single_property_verifier(&verifier0, (initial_message0, final_response0)).is_ok());
        assert!(single_property_verifier(&verifier1, (initial_message1, final_response1)).is_ok());

        // Negative tests
        let bad_initial_message = CorrectnessInitialMessage::default();
        assert_err!(
            single_property_verifier(&verifier0, (bad_initial_message, final_response0)),
            Error::CorrectnessFinalResponseVerificationError { check: 1 }
        );

        let bad_final_response = CorrectnessFinalResponse::from(Scalar::one());
        assert_err!(
            single_property_verifier(&verifier0, (initial_message0, bad_final_response)),
            Error::CorrectnessFinalResponseVerificationError { check: 1 }
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn batched_proofs() {
        let gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_2);
        let pub_key = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();
        let (w, cipher) = pub_key.encrypt_value(6u32.into(), &mut rng);
        let mut transcript = Transcript::new(b"batch_proof_label");

        let (prover0, verifier0) =
            create_correctness_proof_objects_helper(w.clone(), pub_key, cipher, &gens);
        let (prover1, verifier1) =
            create_wellformedness_proof_objects_helper(w, pub_key, cipher, &gens);

        let mut transcript_rng1 = prover0.create_transcript_rng(&mut rng, &transcript);
        let mut transcript_rng2 = prover1.create_transcript_rng(&mut rng, &transcript);

        // Provers generate the initial messages
        let (prover0, initial_message0) = prover0.generate_initial_message(&mut transcript_rng1);
        initial_message0.update_transcript(&mut transcript).unwrap();

        let (prover1, initial_message1) = prover1.generate_initial_message(&mut transcript_rng2);
        initial_message1.update_transcript(&mut transcript).unwrap();

        // Dealer calculates the challenge from the 2 initial messages
        let challenge = transcript
            .scalar_challenge(b"batch_proof_challenge_label")
            .unwrap();

        // Provers generate the final responses
        let final_response0 = prover0.apply_challenge(&challenge);
        let final_response1 = prover1.apply_challenge(&challenge);

        // Positive tests
        // Verifiers verify the proofs
        let result = verifier0.verify(&challenge, &initial_message0, &final_response0);
        assert!(result.is_ok());

        let result = verifier1.verify(&challenge, &initial_message1, &final_response1);
        assert!(result.is_ok());

        // Negative tests
        let bad_challenge = ZKPChallenge::try_from(Scalar::random(&mut rng)).unwrap();
        assert!(verifier0
            .verify(&bad_challenge, &initial_message0, &final_response0)
            .is_err());
        assert!(verifier1
            .verify(&bad_challenge, &initial_message1, &final_response1)
            .is_err());
    }
}
