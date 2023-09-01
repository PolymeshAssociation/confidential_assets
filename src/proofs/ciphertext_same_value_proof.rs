//! The proof of multiple ciphertexts encrypting the same value
//! under different public keys.

use crate::{
    codec_wrapper::{RistrettoPointDecoder, RistrettoPointEncoder, ScalarDecoder, ScalarEncoder},
    elgamal::{CipherText, CommitmentWitness, ElgamalPublicKey},
    errors::{Error, Result},
    proofs::{
        encryption_proofs::{
            ProofProver, ProofProverAwaitingChallenge, ProofVerifier, ZKPChallenge,
            ZKProofResponse,
        },
        transcript::{TranscriptProtocol, UpdateTranscript},
    },
};

use bulletproofs::PedersenGens;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use codec::{Decode, Encode, Error as CodecError, Input, Output};

/// The domain label for the encrypting the same value proof.
pub const ENCRYPTING_SAME_VALUE_PROOF_FINAL_RESPONSE_LABEL: &[u8] =
    b"PolymeshCiphertextSameValueFinalResponse";
/// The domain label for the challenge.
pub const ENCRYPTING_SAME_VALUE_PROOF_CHALLENGE_LABEL: &[u8] =
    b"PolymeshCiphertextSameValueFinalResponseChallenge";

// ------------------------------------------------------------------------
// Proof of multiple Ciphertexts Encrypting the Same Value Under Different
// Public Keys
// ------------------------------------------------------------------------

#[derive(PartialEq, Copy, Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CiphertextSameValueFinalResponse {
    z1: Scalar,
    z2: Scalar,
}

impl Encode for CiphertextSameValueFinalResponse {
    #[inline]
    fn size_hint(&self) -> usize {
        ScalarEncoder(&self.z1).size_hint() + ScalarEncoder(&self.z2).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        ScalarEncoder(&self.z1).encode_to(dest);
        ScalarEncoder(&self.z2).encode_to(dest);
    }
}

impl Decode for CiphertextSameValueFinalResponse {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let z1 = <ScalarDecoder>::decode(input)?.0;
        let z2 = <ScalarDecoder>::decode(input)?.0;

        Ok(CiphertextSameValueFinalResponse { z1, z2 })
    }
}

#[derive(PartialEq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CiphertextSameValueInitialMessage {
    a: Vec<RistrettoPoint>,
    b: RistrettoPoint,
}

impl Encode for CiphertextSameValueInitialMessage {
    #[inline]
    fn size_hint(&self) -> usize {
        let a = self.a.iter().map(|a| RistrettoPointEncoder(a)).collect::<Vec<_>>();
        a.size_hint()
            + RistrettoPointEncoder(&self.b).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        let a = self.a.iter().map(|a| RistrettoPointEncoder(a)).collect::<Vec<_>>();
        a.encode_to(dest);
        RistrettoPointEncoder(&self.b).encode_to(dest);
    }
}

impl Decode for CiphertextSameValueInitialMessage {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let a = <Vec<RistrettoPointDecoder>>::decode(input)?.into_iter().map(|r| r.0).collect();
        let b = <RistrettoPointDecoder>::decode(input)?.0;

        Ok(CiphertextSameValueInitialMessage { a, b })
    }
}

/// A default implementation used for testing.
impl Default for CiphertextSameValueInitialMessage {
    fn default() -> Self {
        CiphertextSameValueInitialMessage {
            a: vec![RISTRETTO_BASEPOINT_POINT],
            b: RISTRETTO_BASEPOINT_POINT,
        }
    }
}

impl UpdateTranscript for CiphertextSameValueInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_domain_separator(ENCRYPTING_SAME_VALUE_PROOF_CHALLENGE_LABEL);
        transcript.append_u64(b"length-A", self.a.len() as u64);
        for a in &self.a {
          transcript.append_validated_point(b"A", &a.compress())?;
        }
        transcript.append_validated_point(b"B", &self.b.compress())?;
        Ok(())
    }
}

/// Holds the non-interactive proofs of equality using different public keys.
pub type CiphertextSameValueProof =
    ZKProofResponse<CiphertextSameValueInitialMessage, CiphertextSameValueFinalResponse>;

pub struct CiphertextSameValueProverAwaitingChallenge<'a> {
    /// The public keys used for the elgamal encryption.
    pub keys: Vec<ElgamalPublicKey>,

    /// The secret commitment witness.
    pub w: CommitmentWitness,

    /// The Pedersen generators.
    pub pc_gens: &'a PedersenGens,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CiphertextSameValueProver {
    /// The secret commitment witness.
    w: CommitmentWitness,

    /// The randomness generated in the first round.
    u1: Scalar,

    /// The randomness generated in the first round.
    u2: Scalar,
}

impl<'a> ProofProverAwaitingChallenge for CiphertextSameValueProverAwaitingChallenge<'a> {
    type ZKInitialMessage = CiphertextSameValueInitialMessage;
    type ZKFinalResponse = CiphertextSameValueFinalResponse;
    type ZKProver = CiphertextSameValueProver;

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
        let rand_commitment1 = Scalar::random(rng);
        let rand_commitment2 = Scalar::random(rng);

        let a = self.keys.iter().map(|key| rand_commitment1 * key.pub_key).collect();

        (
            CiphertextSameValueProver {
                w: self.w.clone(),
                u1: rand_commitment1,
                u2: rand_commitment2,
            },
            CiphertextSameValueInitialMessage {
                a,
                b: rand_commitment1 * self.pc_gens.B_blinding + rand_commitment2 * self.pc_gens.B,
            },
        )
    }
}

impl ProofProver<CiphertextSameValueFinalResponse> for CiphertextSameValueProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> CiphertextSameValueFinalResponse {
        CiphertextSameValueFinalResponse {
            z1: self.u1 + c.x() * self.w.blinding(),
            z2: self.u2 + c.x() * self.w.value(),
        }
    }
}

pub struct CiphertextSameValueVerifier<'a> {
    /// The public keys to which the `value` is encrypted.
    pub keys: Vec<ElgamalPublicKey>,

    /// The encryption cipher texts.
    pub ciphertexts: Vec<CipherText>,

    /// The ciphertext generators.
    pub pc_gens: &'a PedersenGens,
}

impl<'a> ProofVerifier for CiphertextSameValueVerifier<'a> {
    type ZKInitialMessage = CiphertextSameValueInitialMessage;
    type ZKFinalResponse = CiphertextSameValueFinalResponse;

    fn verify(
        &self,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        final_response: &Self::ZKFinalResponse,
    ) -> Result<()> {
        let len = self.keys.len();
        // Ensure there are at least 2 keys (the proof is useless for 0-1 keys).
        ensure!(len >= 2, Error::VerificationError);
        // Ensure the number of keys equals the number of ciphertexts.
        ensure!(len == self.ciphertexts.len(), Error::VerificationError);
        // Ensure the number of keys equals the lenght of `a` from the initial message.
        ensure!(len == initial_message.a.len(), Error::VerificationError);

        // Get the `y` value from the first ciphertext.
        let first_y = self.ciphertexts[0].y;

        ensure!(
            final_response.z1 * self.pc_gens.B_blinding + final_response.z2 * self.pc_gens.B
                == initial_message.b + challenge.x() * first_y,
            Error::CiphertextSameValueFinalResponseVerificationError { check: 0 }
        );

        for ((key, cipher), a) in self.keys.iter().zip(self.ciphertexts.iter()).zip(initial_message.a.iter()) {
            // The ciphertext that encrypt the same witness must have the same Y value.
            ensure!(first_y == cipher.y, Error::VerificationError);

            ensure!(
                final_response.z1 * key.pub_key
                    == a + challenge.x() * cipher.x,
                Error::CiphertextSameValueFinalResponseVerificationError { check: 1 }
            );
        }
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
    fn test_encrypting_same_value_proof() {
        let gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 49u32;

        let elg_pub1 = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();
        let (w, cipher1) = elg_pub1.encrypt_value(secret_value.into(), &mut rng);

        let elg_pub2 = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();
        let cipher2 = elg_pub2.encrypt(&w);

        let prover_ac = CiphertextSameValueProverAwaitingChallenge {
            keys: vec![elg_pub1, elg_pub2],
            w,
            pc_gens: &gens,
        };
        let verifier = CiphertextSameValueVerifier {
            keys: vec![elg_pub1, elg_pub2],
            ciphertexts: vec![cipher1, cipher2],
            pc_gens: &gens,
        };
        let mut transcript = Transcript::new(ENCRYPTING_SAME_VALUE_PROOF_FINAL_RESPONSE_LABEL);

        // Positive tests
        let mut transcript_rng = prover_ac.create_transcript_rng(&mut rng, &transcript);
        let (prover, initial_message) = prover_ac.generate_initial_message(&mut transcript_rng);
        initial_message.update_transcript(&mut transcript).unwrap();
        let challenge = transcript
            .scalar_challenge(ENCRYPTING_SAME_VALUE_PROOF_CHALLENGE_LABEL)
            .unwrap();
        let final_response = prover.apply_challenge(&challenge);

        let result = verifier.verify(&challenge, &initial_message, &final_response);
        assert!(result.is_ok());

        // Negative tests
        let bad_initial_message = CiphertextSameValueInitialMessage::default();
        let result = verifier.verify(&challenge, &bad_initial_message, &final_response);
        assert_err!(
            result,
            Error::VerificationError
        );

        let bad_final_response = CiphertextSameValueFinalResponse::default();
        let result = verifier.verify(&challenge, &initial_message, &bad_final_response);
        assert_err!(
            result,
            Error::CiphertextSameValueFinalResponseVerificationError { check: 0 }
        );

        // Non-Interactive ZKP test
        let proof = encryption_proofs::single_property_prover(prover_ac, &mut rng).unwrap();
        assert!(encryption_proofs::single_property_verifier(&verifier, proof).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn serialize_deserialize_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 49u32;
        let rand_blind = Scalar::random(&mut rng);
        let gens = PedersenGens::default();
        let w = CommitmentWitness::new(secret_value.into(), rand_blind);

        let elg_pub1 = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();
        let elg_pub2 = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();

        let prover = CiphertextSameValueProverAwaitingChallenge {
            keys: vec![elg_pub1, elg_pub2],
            w,
            pc_gens: &gens,
        };

        let (initial_message, final_response) = encryption_proofs::single_property_prover::<
            StdRng,
            CiphertextSameValueProverAwaitingChallenge,
        >(prover, &mut rng)
        .unwrap();

        let bytes = initial_message.encode();
        let mut input: &[u8] = bytes.as_slice();
        let recovered_initial_message =
            <CiphertextSameValueInitialMessage>::decode(&mut input).unwrap();
        assert_eq!(recovered_initial_message, initial_message);

        let bytes = final_response.encode();
        let mut input = bytes.as_slice();
        let recovered_final_response =
            <CiphertextSameValueFinalResponse>::decode(&mut input).unwrap();
        assert_eq!(recovered_final_response, final_response);
    }
}
