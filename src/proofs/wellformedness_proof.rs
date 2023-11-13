//! The proof of the wellformed encryption of the given value.
//! This proofs the knoweledge about the encrypted value.
//! For more details see section 5.1 of the whitepaper.

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

use codec::{Decode, Encode};

/// The domain label for the wellformedness proof.
pub const WELLFORMEDNESS_PROOF_LABEL: &[u8] = b"PolymeshWellformednessProof";
/// The domain label for the challenge.
pub const WELLFORMEDNESS_PROOF_CHALLENGE_LABEL: &[u8] =
    b"PolymeshWellformednessFinalResponseChallenge";

#[derive(PartialEq, Copy, Clone, Encode, Decode, Default, Debug)]
pub struct WellformednessFinalResponse {
    z1: WrappedScalar,
    z2: WrappedScalar,
}

#[derive(PartialEq, Copy, Clone, Encode, Decode, Debug)]
pub struct WellformednessInitialMessage {
    a: WrappedCompressedRistretto,
    b: WrappedCompressedRistretto,
}

/// A default implementation used for testing.
impl Default for WellformednessInitialMessage {
    fn default() -> Self {
        WellformednessInitialMessage {
            a: RISTRETTO_BASEPOINT_POINT.into(),
            b: RISTRETTO_BASEPOINT_POINT.into(),
        }
    }
}

impl UpdateTranscript for WellformednessInitialMessage {
    fn challenge_label() -> &'static [u8] {
        WELLFORMEDNESS_PROOF_CHALLENGE_LABEL
    }

    fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_domain_separator(WELLFORMEDNESS_PROOF_LABEL);
        transcript.append_validated_point(b"A", &self.a.compress())?;
        transcript.append_validated_point(b"B", &self.b.compress())?;
        Ok(())
    }
}

/// Holds the non-interactive proofs of wellformedness, equivalent of L_enc of the MERCAT paper.
pub type WellformednessProof =
    ZKProofResponse<WellformednessInitialMessage, WellformednessFinalResponse>;

#[derive(Clone, Debug)]
pub struct WellformednessProver {
    /// The secret commitment witness.
    w: CommitmentWitness,
    /// The randomness generate in the first round.
    rand_a: Scalar,
    rand_b: Scalar,
}

#[derive(Clone)]
pub struct WellformednessProverAwaitingChallenge<'a> {
    /// The public key used for the elgamal encryption.
    pub pub_key: ElgamalPublicKey,

    /// The secret commitment witness.
    pub w: CommitmentWitness,

    /// The Pedersen generators.
    pub pc_gens: &'a PedersenGens,
}

impl<'a> ProofProverAwaitingChallenge for WellformednessProverAwaitingChallenge<'a> {
    type ZKInitialMessage = WellformednessInitialMessage;
    type ZKFinalResponse = WellformednessFinalResponse;
    type ZKProver = WellformednessProver;

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
        let rand_a = Scalar::random(rng);
        let rand_b = Scalar::random(rng);
        (
            WellformednessProver {
                w: self.w.clone(),
                rand_a,
                rand_b,
            },
            WellformednessInitialMessage {
                a: (rand_a * *self.pub_key.pub_key).into(),
                b: (rand_a * self.pc_gens.B_blinding + rand_b * self.pc_gens.B).into(),
            },
        )
    }
}

impl ProofProver<WellformednessFinalResponse> for WellformednessProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> WellformednessFinalResponse {
        WellformednessFinalResponse {
            z1: (self.rand_a + c.x() * self.w.blinding()).into(),
            z2: (self.rand_b + c.x() * self.w.value()).into(),
        }
    }
}

#[derive(Copy, Clone)]
pub struct WellformednessVerifier<'a> {
    pub pub_key: ElgamalPublicKey,
    pub cipher: CipherText,
    pub pc_gens: &'a PedersenGens,
}

impl<'a> ProofVerifier for WellformednessVerifier<'a> {
    type ZKInitialMessage = WellformednessInitialMessage;
    type ZKFinalResponse = WellformednessFinalResponse;

    fn verify(
        &self,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        response: &Self::ZKFinalResponse,
    ) -> Result<()> {
        let z1 = *response.z1;
        let z2 = *response.z2;
        let a = initial_message.a.decompress();
        let b = initial_message.b.decompress();
        ensure!(
            z1 * *self.pub_key.pub_key == a + challenge.x() * *self.cipher.x,
            Error::WellformednessFinalResponseVerificationError { check: 1 }
        );
        ensure!(
            z1 * self.pc_gens.B_blinding + z2 * self.pc_gens.B
                == b + challenge.x() * *self.cipher.y,
            Error::WellformednessFinalResponseVerificationError { check: 2 }
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::proofs::*;
    use crate::{
        elgamal::ElgamalSecretKey,
        proofs::encryption_proofs::{single_property_prover, single_property_verifier},
    };
    use rand::{rngs::StdRng, SeedableRng};
    use sp_std::prelude::*;
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn test_wellformedness_proof() {
        let gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 42u32;

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pub_key = elg_secret.get_public_key();
        let (w, cipher) = pub_key.encrypt_value(secret_value.into(), &mut rng);

        let prover = WellformednessProverAwaitingChallenge {
            pub_key,
            w: w.clone(),
            pc_gens: &gens,
        };
        let verifier = WellformednessVerifier {
            pub_key,
            cipher,
            pc_gens: &gens,
        };
        let mut dealer_transcript = Transcript::new(WELLFORMEDNESS_PROOF_LABEL);

        // ------------------------------- Interactive case
        // Positive tests
        // 1st round
        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &dealer_transcript);
        let (prover, initial_message) = prover.generate_initial_message(&mut transcript_rng);

        // 2nd round
        initial_message
            .update_transcript(&mut dealer_transcript)
            .unwrap();
        let challenge = dealer_transcript
            .scalar_challenge(WELLFORMEDNESS_PROOF_CHALLENGE_LABEL)
            .unwrap();

        // 3rd round
        let final_response = prover.apply_challenge(&challenge);

        // 4th round
        // in the interactive case, verifier is the dealer and therefore, the challenge is saved
        // on the verifier side and passed to this function.
        let result = verifier.verify(&challenge, &initial_message, &final_response);
        assert!(result.is_ok());

        // Negative tests
        let bad_initial_message = WellformednessInitialMessage::default();
        let result = verifier.verify(&challenge, &bad_initial_message, &final_response);
        assert_err!(
            result,
            Error::WellformednessFinalResponseVerificationError { check: 1 }
        );

        let bad_final_response = WellformednessFinalResponse::default();
        let result = verifier.verify(&challenge, &initial_message, &bad_final_response);
        assert_err!(
            result,
            Error::WellformednessFinalResponseVerificationError { check: 1 }
        );

        // ------------------------------- Non-interactive case
        let prover = WellformednessProverAwaitingChallenge {
            pub_key,
            w,
            pc_gens: &gens,
        };
        let verifier = WellformednessVerifier {
            pub_key,
            cipher,
            pc_gens: &gens,
        };

        // 1st to 3rd rounds
        let (initial_message, final_response) = single_property_prover::<
            StdRng,
            WellformednessProverAwaitingChallenge,
        >(prover, &mut rng)
        .unwrap();

        // Positive test
        assert!(
            // 4th round
            single_property_verifier(&verifier, &(initial_message, final_response)).is_ok()
        );

        // Negative tests
        let bad_initial_message = WellformednessInitialMessage::default();
        assert_err!(
            // 4th round
            single_property_verifier(&verifier, &(bad_initial_message, final_response)),
            Error::WellformednessFinalResponseVerificationError { check: 1 }
        );

        assert_err!(
            // 4th round
            single_property_verifier(&verifier, &(initial_message, bad_final_response)),
            Error::WellformednessFinalResponseVerificationError { check: 1 }
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn serialize_deserialize_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 42u32;
        let rand_blind = Scalar::random(&mut rng);
        let gens = PedersenGens::default();
        let w = CommitmentWitness::new(secret_value.into(), rand_blind);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pub_key = elg_secret.get_public_key();

        let prover = WellformednessProverAwaitingChallenge {
            pub_key,
            w,
            pc_gens: &gens,
        };
        let (initial_message, final_response) = encryption_proofs::single_property_prover::<
            StdRng,
            WellformednessProverAwaitingChallenge,
        >(prover, &mut rng)
        .unwrap();

        let bytes = initial_message.encode();
        let mut input = bytes.as_slice();
        let recovered_initial_message = <WellformednessInitialMessage>::decode(&mut input).unwrap();
        assert_eq!(recovered_initial_message, initial_message);

        let bytes = final_response.encode();
        let mut input = bytes.as_slice();
        let recovered_final_response = <WellformednessFinalResponse>::decode(&mut input).unwrap();
        assert_eq!(recovered_final_response, final_response);
    }
}
