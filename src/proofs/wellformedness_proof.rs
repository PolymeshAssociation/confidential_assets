//! The proof of the wellformed encryption of the given value.
//! This proofs the knoweledge about the encrypted value.
//! For more details see section 5.1 of the whitepaper.

use crate::{
    errors::{ErrorKind, Fallible},
    proofs::{
        encryption_proofs::{
            AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
            ZKProofResponse,
        },
        transcript::{TranscriptProtocol, UpdateTranscript},
    },
    elgamal::{
        CipherText, CommitmentWitness, ElgamalPublicKey,
    },
    codec_wrapper::{RistrettoPointDecoder, RistrettoPointEncoder, ScalarDecoder, ScalarEncoder},
};

use bulletproofs::PedersenGens;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use codec::{Decode, Encode, Error as CodecError, Input, Output};

/// The domain label for the wellformedness proof.
pub const WELLFORMEDNESS_PROOF_FINAL_RESPONSE_LABEL: &[u8] = b"PolymeshWellformednessFinalResponse";
/// The domain label for the challenge.
pub const WELLFORMEDNESS_PROOF_CHALLENGE_LABEL: &[u8] = b"PolymeshWellformednessProofChallenge";

#[derive(PartialEq, Copy, Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WellformednessFinalResponse {
    z1: Scalar,
    z2: Scalar,
}

impl Encode for WellformednessFinalResponse {
    fn size_hint(&self) -> usize {
        ScalarEncoder(&self.z1).size_hint() + ScalarEncoder(&self.z2).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        ScalarEncoder(&self.z1).encode_to(dest);
        ScalarEncoder(&self.z2).encode_to(dest);
    }
}

impl Decode for WellformednessFinalResponse {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let z1 = <ScalarDecoder>::decode(input)?.0;
        let z2 = <ScalarDecoder>::decode(input)?.0;

        Ok(WellformednessFinalResponse { z1, z2 })
    }
}

#[derive(PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WellformednessInitialMessage {
    a: RistrettoPoint,
    b: RistrettoPoint,
}

/// A default implementation used for testing.
impl Default for WellformednessInitialMessage {
    fn default() -> Self {
        WellformednessInitialMessage {
            a: RISTRETTO_BASEPOINT_POINT,
            b: RISTRETTO_BASEPOINT_POINT,
        }
    }
}

impl Encode for WellformednessInitialMessage {
    #[inline]
    fn size_hint(&self) -> usize {
        RistrettoPointEncoder(&self.a).size_hint() + RistrettoPointEncoder(&self.b).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        RistrettoPointEncoder(&self.a).encode_to(dest);
        RistrettoPointEncoder(&self.b).encode_to(dest);
    }
}

impl Decode for WellformednessInitialMessage {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let a = <RistrettoPointDecoder>::decode(input)?.0;
        let b = <RistrettoPointDecoder>::decode(input)?.0;

        Ok(WellformednessInitialMessage { a, b })
    }
}

impl UpdateTranscript for WellformednessInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Fallible<()> {
        transcript.append_domain_separator(WELLFORMEDNESS_PROOF_CHALLENGE_LABEL);
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
    w: Zeroizing<CommitmentWitness>,
    /// The randomness generate in the first round.
    rand_a: Scalar,
    rand_b: Scalar,
}

#[derive(Clone)]
pub struct WellformednessProverAwaitingChallenge<'a> {
    /// The public key used for the elgamal encryption.
    pub pub_key: ElgamalPublicKey,

    /// The secret commitment witness.
    pub w: Zeroizing<CommitmentWitness>,

    /// The Pedersen generators.
    pub pc_gens: &'a PedersenGens,
}

impl<'a> AssetProofProverAwaitingChallenge for WellformednessProverAwaitingChallenge<'a> {
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
                a: rand_a * self.pub_key.pub_key,
                b: rand_a * self.pc_gens.B_blinding + rand_b * self.pc_gens.B,
            },
        )
    }
}

impl AssetProofProver<WellformednessFinalResponse> for WellformednessProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> WellformednessFinalResponse {
        WellformednessFinalResponse {
            z1: self.rand_a + c.x() * self.w.blinding(),
            z2: self.rand_b + c.x() * self.w.value(),
        }
    }
}

#[derive(Copy, Clone)]
pub struct WellformednessVerifier<'a> {
    pub pub_key: ElgamalPublicKey,
    pub cipher: CipherText,
    pub pc_gens: &'a PedersenGens,
}

impl<'a> AssetProofVerifier for WellformednessVerifier<'a> {
    type ZKInitialMessage = WellformednessInitialMessage;
    type ZKFinalResponse = WellformednessFinalResponse;

    fn verify(
        &self,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        response: &Self::ZKFinalResponse,
    ) -> Fallible<()> {
        ensure!(
            response.z1 * self.pub_key.pub_key == initial_message.a + challenge.x() * self.cipher.x,
            ErrorKind::WellformednessFinalResponseVerificationError { check: 1 }
        );
        ensure!(
            response.z1 * self.pc_gens.B_blinding + response.z2 * self.pc_gens.B
                == initial_message.b + challenge.x() * self.cipher.y,
            ErrorKind::WellformednessFinalResponseVerificationError { check: 2 }
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::{
        proofs::encryption_proofs::{
            single_property_prover, single_property_verifier,
        },
        elgamal::ElgamalSecretKey,
    };
    use crate::proofs::*;
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
            w: Zeroizing::new(w.clone()),
            pc_gens: &gens,
        };
        let verifier = WellformednessVerifier {
            pub_key,
            cipher,
            pc_gens: &gens,
        };
        let mut dealer_transcript = Transcript::new(WELLFORMEDNESS_PROOF_FINAL_RESPONSE_LABEL);

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
            ErrorKind::WellformednessFinalResponseVerificationError { check: 1 }
        );

        let bad_final_response = WellformednessFinalResponse {
            z1: Scalar::default(),
            z2: Scalar::default(),
        };
        let result = verifier.verify(&challenge, &initial_message, &bad_final_response);
        assert_err!(
            result,
            ErrorKind::WellformednessFinalResponseVerificationError { check: 1 }
        );

        // ------------------------------- Non-interactive case
        let prover = WellformednessProverAwaitingChallenge {
            pub_key,
            w: Zeroizing::new(w),
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
            single_property_verifier(&verifier, (initial_message, final_response)).is_ok()
        );

        // Negative tests
        let bad_initial_message = WellformednessInitialMessage::default();
        assert_err!(
            // 4th round
            single_property_verifier(&verifier, (bad_initial_message, final_response)),
            ErrorKind::WellformednessFinalResponseVerificationError { check: 1 }
        );

        assert_err!(
            // 4th round
            single_property_verifier(&verifier, (initial_message, bad_final_response)),
            ErrorKind::WellformednessFinalResponseVerificationError { check: 1 }
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
            w: Zeroizing::new(w),
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
