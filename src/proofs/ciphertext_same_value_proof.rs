//! The proof of multiple ciphertexts encrypting the same value
//! under different public keys.

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

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use codec::{Decode, Encode};

/// The domain label for the encrypting the same value proof.
pub const CIPHERTEXT_SAME_VALUE_PROOF_LABEL: &[u8] = b"PolymeshCipherTextSameValueProof";
/// The domain label for the challenge.
pub const CIPHERTEXT_SAME_VALUE_PROOF_CHALLENGE_LABEL: &[u8] =
    b"PolymeshCipherTextSameValueFinalResponseChallenge";

// ------------------------------------------------------------------------
// Proof of multiple CipherTexts Encrypting the Same Value Under Different
// Public Keys
// ------------------------------------------------------------------------

#[derive(PartialEq, Copy, Clone, Encode, Decode, Default, Debug)]
pub struct CipherTextSameValueFinalResponse {
    z1: WrappedScalar,
    z2: WrappedScalar,
}

#[derive(PartialEq, Clone, Encode, Decode, Debug)]
pub struct CipherTextSameValueInitialMessage {
    a: Vec<WrappedCompressedRistretto>,
    b: WrappedCompressedRistretto,
}

/// A default implementation used for testing.
impl Default for CipherTextSameValueInitialMessage {
    fn default() -> Self {
        CipherTextSameValueInitialMessage {
            a: vec![RISTRETTO_BASEPOINT_POINT.into()],
            b: RISTRETTO_BASEPOINT_POINT.into(),
        }
    }
}

impl UpdateTranscript for CipherTextSameValueInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<ZKPChallenge> {
        transcript.append_u64(b"length-A", self.a.len() as u64);
        for a in &self.a {
            transcript.append_validated_point(b"A", &a.compress())?;
        }
        transcript.append_validated_point(b"B", &self.b.compress())?;
        transcript.scalar_challenge(CIPHERTEXT_SAME_VALUE_PROOF_CHALLENGE_LABEL)
    }
}

pub struct CipherTextSameValueInputs {
    /// The public keys to which the `value` is encrypted.
    pub keys: Vec<ElgamalPublicKey>,

    /// The encryption cipher texts.
    pub ciphertexts: Vec<CipherText>,
}

impl CipherTextSameValueInputs {
    pub fn new(keys: Vec<ElgamalPublicKey>, ciphertexts: Vec<CipherText>) -> Self {
        Self { keys, ciphertexts }
    }

    fn start_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_domain_separator(CIPHERTEXT_SAME_VALUE_PROOF_LABEL);
        for key in &self.keys {
            transcript.append_validated_point(b"PK", &key.pub_key.compress())?;
        }
        let first = self
            .ciphertexts
            .first()
            .ok_or_else(|| Error::VerificationError)?;
        transcript.append_validated_point(b"Y", &first.y.compress())?;
        for ciphertext in &self.ciphertexts {
            transcript.append_validated_point(b"X", &ciphertext.x.compress())?;
        }
        Ok(())
    }
}

/// Holds the non-interactive proofs of equality using different public keys.
pub type CipherTextSameValueProof =
    ZKProofResponse<CipherTextSameValueInitialMessage, CipherTextSameValueFinalResponse>;

pub struct CipherTextSameValueProverAwaitingChallenge<'a> {
    pub inputs: CipherTextSameValueInputs,

    /// The secret commitment witness.
    pub w: CommitmentWitness,

    /// The Pedersen generators.
    pub pc_gens: &'a PedersenGens,
}

impl<'a> CipherTextSameValueProverAwaitingChallenge<'a> {
    pub fn new(
        keys: Vec<ElgamalPublicKey>,
        ciphertexts: Vec<CipherText>,
        w: CommitmentWitness,
        pc_gens: &'a PedersenGens,
    ) -> Self {
        Self {
            inputs: CipherTextSameValueInputs::new(keys, ciphertexts),
            w,
            pc_gens,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherTextSameValueProver {
    /// The secret commitment witness.
    w: CommitmentWitness,

    /// The randomness generated in the first round.
    u1: Scalar,

    /// The randomness generated in the first round.
    u2: Scalar,
}

impl<'a> ProofProverAwaitingChallenge for CipherTextSameValueProverAwaitingChallenge<'a> {
    type ZKInitialMessage = CipherTextSameValueInitialMessage;
    type ZKFinalResponse = CipherTextSameValueFinalResponse;
    type ZKProver = CipherTextSameValueProver;

    fn start_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        self.inputs.start_transcript(transcript)
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
        let rand_commitment1 = Scalar::random(rng);
        let rand_commitment2 = Scalar::random(rng);

        let a = self
            .inputs
            .keys
            .iter()
            .map(|key| (rand_commitment1 * *key.pub_key).into())
            .collect();

        (
            CipherTextSameValueProver {
                w: self.w.clone(),
                u1: rand_commitment1,
                u2: rand_commitment2,
            },
            CipherTextSameValueInitialMessage {
                a,
                b: (rand_commitment1 * self.pc_gens.B_blinding + rand_commitment2 * self.pc_gens.B)
                    .into(),
            },
        )
    }
}

impl ProofProver<CipherTextSameValueFinalResponse> for CipherTextSameValueProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> CipherTextSameValueFinalResponse {
        CipherTextSameValueFinalResponse {
            z1: (self.u1 + c.x() * self.w.blinding()).into(),
            z2: (self.u2 + c.x() * self.w.value()).into(),
        }
    }
}

pub struct CipherTextSameValueVerifier<'a> {
    pub inputs: CipherTextSameValueInputs,

    /// The ciphertext generators.
    pub pc_gens: &'a PedersenGens,
}

impl<'a> CipherTextSameValueVerifier<'a> {
    pub fn new(
        keys: Vec<ElgamalPublicKey>,
        ciphertexts: Vec<CipherText>,
        pc_gens: &'a PedersenGens,
    ) -> Self {
        Self {
            inputs: CipherTextSameValueInputs::new(keys, ciphertexts),
            pc_gens,
        }
    }
}

impl<'a> ProofVerifier for CipherTextSameValueVerifier<'a> {
    type ZKInitialMessage = CipherTextSameValueInitialMessage;
    type ZKFinalResponse = CipherTextSameValueFinalResponse;

    fn start_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        self.inputs.start_transcript(transcript)
    }

    fn verify(
        &self,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        final_response: &Self::ZKFinalResponse,
    ) -> Result<()> {
        let len = self.inputs.keys.len();
        // Ensure there are at least 2 keys (the proof is useless for 0-1 keys).
        ensure!(len >= 2, Error::VerificationError);
        // Ensure the number of keys equals the number of ciphertexts.
        ensure!(
            len == self.inputs.ciphertexts.len(),
            Error::VerificationError
        );
        // Ensure the number of keys equals the lenght of `a` from the initial message.
        ensure!(len == initial_message.a.len(), Error::VerificationError);

        // Get the `y` value from the first ciphertext.
        let first_y = *self.inputs.ciphertexts[0].y;

        let z1 = *final_response.z1;
        let z2 = *final_response.z2;
        let b = initial_message.b.decompress();
        ensure!(
            z1 * self.pc_gens.B_blinding + z2 * self.pc_gens.B == b + challenge.x() * first_y,
            Error::CiphertextSameValueFinalResponseVerificationError { check: 0 }
        );

        for ((key, cipher), a) in self
            .inputs
            .keys
            .iter()
            .zip(self.inputs.ciphertexts.iter())
            .zip(initial_message.a.iter())
        {
            let a = a.decompress();
            // The ciphertext that encrypt the same witness must have the same Y value.
            ensure!(first_y == *cipher.y, Error::VerificationError);

            ensure!(
                z1 * *key.pub_key == a + challenge.x() * *cipher.x,
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

        let prover_ac = CipherTextSameValueProverAwaitingChallenge::new(
            vec![elg_pub1, elg_pub2],
            vec![cipher1, cipher2],
            w,
            &gens,
        );
        let verifier = CipherTextSameValueVerifier::new(
            vec![elg_pub1, elg_pub2],
            vec![cipher1, cipher2],
            &gens,
        );
        let mut transcript = Transcript::new(CIPHERTEXT_SAME_VALUE_PROOF_LABEL);

        // Positive tests
        let mut transcript_rng = prover_ac.create_transcript_rng(&mut rng, &transcript);
        let (prover, initial_message) = prover_ac.generate_initial_message(&mut transcript_rng);
        let challenge = initial_message.update_transcript(&mut transcript).unwrap();
        let final_response = prover.apply_challenge(&challenge);

        let result = verifier.verify(&challenge, &initial_message, &final_response);
        assert!(result.is_ok());

        // Negative tests
        let bad_initial_message = CipherTextSameValueInitialMessage::default();
        let result = verifier.verify(&challenge, &bad_initial_message, &final_response);
        assert_err!(result, Error::VerificationError);

        let bad_final_response = CipherTextSameValueFinalResponse::default();
        let result = verifier.verify(&challenge, &initial_message, &bad_final_response);
        assert_err!(
            result,
            Error::CiphertextSameValueFinalResponseVerificationError { check: 0 }
        );

        // Non-Interactive ZKP test
        let proof = encryption_proofs::single_property_prover(prover_ac, &mut rng).unwrap();
        assert!(encryption_proofs::single_property_verifier(&verifier, &proof).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn serialize_deserialize_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = 49u32;
        let gens = PedersenGens::default();

        let elg_pub1 = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();
        let (w, cipher1) = elg_pub1.encrypt_value(secret_value.into(), &mut rng);

        let elg_pub2 = ElgamalSecretKey::new(Scalar::random(&mut rng)).get_public_key();
        let cipher2 = elg_pub2.encrypt(&w);

        let prover = CipherTextSameValueProverAwaitingChallenge::new(
            vec![elg_pub1, elg_pub2],
            vec![cipher1, cipher2],
            w,
            &gens,
        );

        let (initial_message, final_response) = encryption_proofs::single_property_prover::<
            StdRng,
            CipherTextSameValueProverAwaitingChallenge,
        >(prover, &mut rng)
        .unwrap();

        let bytes = initial_message.encode();
        let mut input: &[u8] = bytes.as_slice();
        let recovered_initial_message =
            <CipherTextSameValueInitialMessage>::decode(&mut input).unwrap();
        assert_eq!(recovered_initial_message, initial_message);

        let bytes = final_response.encode();
        let mut input = bytes.as_slice();
        let recovered_final_response =
            <CipherTextSameValueFinalResponse>::decode(&mut input).unwrap();
        assert_eq!(recovered_final_response, final_response);
    }
}
