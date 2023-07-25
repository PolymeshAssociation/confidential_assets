//! The proof of two ciphertexts encrypting the same value
//! under different public keys.
//! For more details see section 5.4 of the whitepaper.

use crate::{
    codec_wrapper::{RistrettoPointDecoder, RistrettoPointEncoder, ScalarDecoder, ScalarEncoder},
    elgamal::{CipherText, CommitmentWitness, ElgamalPublicKey},
    errors::{ErrorKind, Fallible},
    proofs::{
        encryption_proofs::{
            AssetProofProver, AssetProofProverAwaitingChallenge, AssetProofVerifier, ZKPChallenge,
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
use zeroize::{Zeroize, Zeroizing};

use codec::{Decode, Encode, Error as CodecError, Input, Output};

/// The domain label for the encrypting the same value proof.
pub const ENCRYPTING_SAME_VALUE_PROOF_FINAL_RESPONSE_LABEL: &[u8] =
    b"PolymeshEncryptingSameValueFinalResponse";
/// The domain label for the challenge.
pub const ENCRYPTING_SAME_VALUE_PROOF_CHALLENGE_LABEL: &[u8] =
    b"PolymeshEncryptingSameValueFinalResponseChallenge";

// ------------------------------------------------------------------------
// Proof of Two Ciphertexts Encrypting the Same Value Under Different
// Public Keys
// ------------------------------------------------------------------------

#[derive(PartialEq, Copy, Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EncryptingSameValueFinalResponse {
    z1: Scalar,
    z2: Scalar,
}

impl Encode for EncryptingSameValueFinalResponse {
    #[inline]
    fn size_hint(&self) -> usize {
        ScalarEncoder(&self.z1).size_hint() + ScalarEncoder(&self.z2).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        ScalarEncoder(&self.z1).encode_to(dest);
        ScalarEncoder(&self.z2).encode_to(dest);
    }
}

impl Decode for EncryptingSameValueFinalResponse {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let z1 = <ScalarDecoder>::decode(input)?.0;
        let z2 = <ScalarDecoder>::decode(input)?.0;

        Ok(EncryptingSameValueFinalResponse { z1, z2 })
    }
}

#[derive(PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EncryptingSameValueInitialMessage {
    a1: RistrettoPoint,
    a2: RistrettoPoint,
    b: RistrettoPoint,
}

impl Encode for EncryptingSameValueInitialMessage {
    #[inline]
    fn size_hint(&self) -> usize {
        RistrettoPointEncoder(&self.a1).size_hint()
            + RistrettoPointEncoder(&self.a2).size_hint()
            + RistrettoPointEncoder(&self.b).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        RistrettoPointEncoder(&self.a1).encode_to(dest);
        RistrettoPointEncoder(&self.a2).encode_to(dest);
        RistrettoPointEncoder(&self.b).encode_to(dest);
    }
}

impl Decode for EncryptingSameValueInitialMessage {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let a1 = <RistrettoPointDecoder>::decode(input)?.0;
        let a2 = <RistrettoPointDecoder>::decode(input)?.0;
        let b = <RistrettoPointDecoder>::decode(input)?.0;

        Ok(EncryptingSameValueInitialMessage { a1, a2, b })
    }
}

/// A default implementation used for testing.
impl Default for EncryptingSameValueInitialMessage {
    fn default() -> Self {
        EncryptingSameValueInitialMessage {
            a1: RISTRETTO_BASEPOINT_POINT,
            a2: RISTRETTO_BASEPOINT_POINT,
            b: RISTRETTO_BASEPOINT_POINT,
        }
    }
}

impl UpdateTranscript for EncryptingSameValueInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Fallible<()> {
        transcript.append_domain_separator(ENCRYPTING_SAME_VALUE_PROOF_CHALLENGE_LABEL);
        transcript.append_validated_point(b"A1", &self.a1.compress())?;
        transcript.append_validated_point(b"A2", &self.a2.compress())?;
        transcript.append_validated_point(b"B", &self.b.compress())?;
        Ok(())
    }
}

/// Holds the non-interactive proofs of equality using different public keys, equivalent
/// of L_cipher of the MERCAT paper.
pub type CipherEqualDifferentPubKeyProof =
    ZKProofResponse<EncryptingSameValueInitialMessage, EncryptingSameValueFinalResponse>;

pub struct EncryptingSameValueProverAwaitingChallenge<'a> {
    /// The first public key used for the elgamal encryption.
    pub pub_key1: ElgamalPublicKey,

    /// The second public key used for the elgamal encryption.
    pub pub_key2: ElgamalPublicKey,

    /// The secret commitment witness.
    pub w: Zeroizing<CommitmentWitness>,

    /// The Pedersen generators.
    pub pc_gens: &'a PedersenGens,
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EncryptingSameValueProver {
    /// The secret commitment witness.
    w: Zeroizing<CommitmentWitness>,

    /// The randomness generated in the first round.
    u1: Scalar,

    /// The randomness generated in the first round.
    u2: Scalar,
}

impl<'a> AssetProofProverAwaitingChallenge for EncryptingSameValueProverAwaitingChallenge<'a> {
    type ZKInitialMessage = EncryptingSameValueInitialMessage;
    type ZKFinalResponse = EncryptingSameValueFinalResponse;
    type ZKProver = EncryptingSameValueProver;

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

        (
            EncryptingSameValueProver {
                w: self.w.clone(),
                u1: rand_commitment1,
                u2: rand_commitment2,
            },
            EncryptingSameValueInitialMessage {
                a1: rand_commitment1 * self.pub_key1.pub_key,
                a2: rand_commitment1 * self.pub_key2.pub_key,
                b: rand_commitment1 * self.pc_gens.B_blinding + rand_commitment2 * self.pc_gens.B,
            },
        )
    }
}

impl AssetProofProver<EncryptingSameValueFinalResponse> for EncryptingSameValueProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> EncryptingSameValueFinalResponse {
        EncryptingSameValueFinalResponse {
            z1: self.u1 + c.x() * self.w.blinding(),
            z2: self.u2 + c.x() * self.w.value(),
        }
    }
}

pub struct EncryptingSameValueVerifier<'a> {
    /// The first public key to which the `value` is encrypted.
    pub pub_key1: ElgamalPublicKey,

    /// The second public key to which the `value` is encrypted.
    pub pub_key2: ElgamalPublicKey,

    /// The first encryption cipher text.
    pub cipher1: CipherText,

    /// The second encryption cipher text.
    pub cipher2: CipherText,

    /// The ciphertext generators.
    pub pc_gens: &'a PedersenGens,
}

impl<'a> AssetProofVerifier for EncryptingSameValueVerifier<'a> {
    type ZKInitialMessage = EncryptingSameValueInitialMessage;
    type ZKFinalResponse = EncryptingSameValueFinalResponse;

    fn verify(
        &self,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        final_response: &Self::ZKFinalResponse,
    ) -> Fallible<()> {
        // 2 ciphertexts that encrypt the same witness must have the same Y value.
        ensure!(
            self.cipher1.y == self.cipher2.y,
            ErrorKind::VerificationError
        );

        ensure!(
            final_response.z1 * self.pub_key1.pub_key
                == initial_message.a1 + challenge.x() * self.cipher1.x,
            ErrorKind::EncryptingSameValueFinalResponseVerificationError { check: 1 }
        );
        ensure!(
            final_response.z1 * self.pub_key2.pub_key
                == initial_message.a2 + challenge.x() * self.cipher2.x,
            ErrorKind::EncryptingSameValueFinalResponseVerificationError { check: 2 }
        );
        ensure!(
            final_response.z1 * self.pc_gens.B_blinding + final_response.z2 * self.pc_gens.B
                == initial_message.b + challenge.x() * self.cipher1.y,
            ErrorKind::EncryptingSameValueFinalResponseVerificationError { check: 3 }
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
    fn test_encrypting_same_value_proof() {
        let gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 49u32;

        let elg_pub1 = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();
        let (w, cipher1) = elg_pub1.encrypt_value(secret_value.into(), &mut rng);

        let elg_pub2 = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();
        let cipher2 = elg_pub2.encrypt(&w);

        let prover_ac = EncryptingSameValueProverAwaitingChallenge {
            pub_key1: elg_pub1,
            pub_key2: elg_pub2,
            w: Zeroizing::new(w),
            pc_gens: &gens,
        };
        let verifier = EncryptingSameValueVerifier {
            pub_key1: elg_pub1,
            pub_key2: elg_pub2,
            cipher1,
            cipher2,
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
        let bad_initial_message = EncryptingSameValueInitialMessage::default();
        let result = verifier.verify(&challenge, &bad_initial_message, &final_response);
        assert_err!(
            result,
            ErrorKind::EncryptingSameValueFinalResponseVerificationError { check: 1 }
        );

        let bad_final_response = EncryptingSameValueFinalResponse::default();
        let result = verifier.verify(&challenge, &initial_message, &bad_final_response);
        assert_err!(
            result,
            ErrorKind::EncryptingSameValueFinalResponseVerificationError { check: 1 }
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

        let prover = EncryptingSameValueProverAwaitingChallenge {
            pub_key1: elg_pub1,
            pub_key2: elg_pub2,
            w: Zeroizing::new(w),
            pc_gens: &gens,
        };

        let (initial_message, final_response) = encryption_proofs::single_property_prover::<
            StdRng,
            EncryptingSameValueProverAwaitingChallenge,
        >(prover, &mut rng)
        .unwrap();

        let bytes = initial_message.encode();
        let mut input: &[u8] = bytes.as_slice();
        let recovered_initial_message =
            <EncryptingSameValueInitialMessage>::decode(&mut input).unwrap();
        assert_eq!(recovered_initial_message, initial_message);

        let bytes = final_response.encode();
        let mut input = bytes.as_slice();
        let recovered_final_response =
            <EncryptingSameValueFinalResponse>::decode(&mut input).unwrap();
        assert_eq!(recovered_final_response, final_response);
    }
}
