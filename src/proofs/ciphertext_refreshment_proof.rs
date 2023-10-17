//! The proof that 2 cipher texts encrypt the same value
//! under the same public key.
//! This proof is useful to prove the correctness of a
//! ciphertext refreshment method.
//! For more details see sections 3.6 and 5.3 of the
//! whitepaper.

use crate::{
    codec_wrapper::{WrappedCompressedRistretto, WrappedScalar},
    elgamal::{CipherText, ElgamalPublicKey, ElgamalSecretKey},
    errors::{Error, Result},
    proofs::{
        encryption_proofs::{
            ProofProver, ProofProverAwaitingChallenge, ProofVerifier, ZKPChallenge, ZKProofResponse,
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
use zeroize::{Zeroize, ZeroizeOnDrop};

use codec::{Decode, Encode};

/// The domain label for the ciphertext refreshment proof.
pub const CIPHERTEXT_REFRESHMENT_FINAL_RESPONSE_LABEL: &[u8] =
    b"PolymeshCipherTextRefreshmentFinalResponse";
/// The domain label for the challenge.
pub const CIPHERTEXT_REFRESHMENT_PROOF_CHALLENGE_LABEL: &[u8] =
    b"PolymeshCipherTextRefreshmentChallenge";

// ------------------------------------------------------------------------
// Proof of two ciphertext encrypting the same value under the same
// public key
// ------------------------------------------------------------------------

#[derive(PartialEq, Copy, Clone, Encode, Decode, Default, Debug)]
pub struct CipherTextRefreshmentFinalResponse(pub WrappedScalar);

#[derive(PartialEq, Copy, Clone, Encode, Decode, Debug)]
pub struct CipherTextRefreshmentInitialMessage {
    pub a: WrappedCompressedRistretto,
    pub b: WrappedCompressedRistretto,
}

/// A default implementation used for testing.
impl Default for CipherTextRefreshmentInitialMessage {
    fn default() -> Self {
        CipherTextRefreshmentInitialMessage {
            a: RISTRETTO_BASEPOINT_POINT.into(),
            b: RISTRETTO_BASEPOINT_POINT.into(),
        }
    }
}

impl UpdateTranscript for CipherTextRefreshmentInitialMessage {
    fn update_transcript(&self, transcript: &mut Transcript) -> Result<()> {
        transcript.append_domain_separator(CIPHERTEXT_REFRESHMENT_PROOF_CHALLENGE_LABEL);
        transcript.append_validated_point(b"A", &self.a.compress())?;
        transcript.append_validated_point(b"B", &self.b.compress())?;
        Ok(())
    }
}

/// Holds the non-interactive proofs of equality using different public keys, equivalent
/// of L_equal of MERCAT paper.
pub type CipherEqualSamePubKeyProof =
    ZKProofResponse<CipherTextRefreshmentInitialMessage, CipherTextRefreshmentFinalResponse>;

pub struct CipherTextRefreshmentProverAwaitingChallenge<'a> {
    /// The public key used for the elgamal encryption.
    secret_key: ElgamalSecretKey,

    /// The difference between the Y part of the two ciphertexts:
    /// Y = ciphertext1.y - ciphertext2.y
    y: RistrettoPoint,
    pc_gens: &'a PedersenGens,
}

impl<'a> CipherTextRefreshmentProverAwaitingChallenge<'a> {
    pub fn new(
        secret_key: ElgamalSecretKey,
        ciphertext1: CipherText,
        ciphertext2: CipherText,
        gens: &'a PedersenGens,
    ) -> Self {
        CipherTextRefreshmentProverAwaitingChallenge {
            secret_key,
            y: *ciphertext1.y - *ciphertext2.y,
            pc_gens: gens,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherTextRefreshmentProver {
    /// The secret key.
    secret_key: Scalar,

    /// The randomness generated in the first round.
    u: Scalar,
}

impl<'a> ProofProverAwaitingChallenge for CipherTextRefreshmentProverAwaitingChallenge<'a> {
    type ZKInitialMessage = CipherTextRefreshmentInitialMessage;
    type ZKFinalResponse = CipherTextRefreshmentFinalResponse;
    type ZKProver = CipherTextRefreshmentProver;

    fn create_transcript_rng<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        transcript: &Transcript,
    ) -> TranscriptRng {
        transcript
            .build_rng()
            .rekey_with_witness_bytes(b"y", self.y.compress().as_bytes())
            .finalize(rng)
    }

    fn generate_initial_message(
        &self,
        rng: &mut TranscriptRng,
    ) -> (Self::ZKProver, Self::ZKInitialMessage) {
        let rand_commitment = Scalar::random(rng);

        let initial_message = CipherTextRefreshmentInitialMessage {
            a: (rand_commitment * self.y).into(),
            b: (rand_commitment * self.pc_gens.B_blinding).into(),
        };

        let prover = CipherTextRefreshmentProver {
            secret_key: self.secret_key.secret(),
            u: rand_commitment,
        };
        (prover, initial_message)
    }
}

impl ProofProver<CipherTextRefreshmentFinalResponse> for CipherTextRefreshmentProver {
    fn apply_challenge(&self, c: &ZKPChallenge) -> CipherTextRefreshmentFinalResponse {
        CipherTextRefreshmentFinalResponse((self.u + c.x() * self.secret_key).into())
    }
}

pub struct CipherTextRefreshmentVerifier<'a> {
    /// The public key to which the `value` is encrypted.
    pub pub_key: ElgamalPublicKey,

    /// The difference between the X part of the two ciphertexts:
    /// X = ciphertext1.x - ciphertext2.x
    pub x: RistrettoPoint,

    /// The difference between the Y part of the two ciphertexts:
    /// Y = ciphertext1.y - ciphertext2.y
    pub y: RistrettoPoint,
    pub pc_gens: &'a PedersenGens,
}

impl<'a> CipherTextRefreshmentVerifier<'a> {
    pub fn new(
        pub_key: ElgamalPublicKey,
        ciphertext1: CipherText,
        ciphertext2: CipherText,
        gens: &'a PedersenGens,
    ) -> Self {
        CipherTextRefreshmentVerifier {
            pub_key,
            x: *ciphertext1.x - *ciphertext2.x,
            y: *ciphertext1.y - *ciphertext2.y,
            pc_gens: gens,
        }
    }
}

impl<'a> ProofVerifier for CipherTextRefreshmentVerifier<'a> {
    type ZKInitialMessage = CipherTextRefreshmentInitialMessage;
    type ZKFinalResponse = CipherTextRefreshmentFinalResponse;

    fn verify(
        &self,
        challenge: &ZKPChallenge,
        initial_message: &Self::ZKInitialMessage,
        z: &Self::ZKFinalResponse,
    ) -> Result<()> {
        let z = *z.0;
        let a = initial_message.a.decompress();
        let b = initial_message.b.decompress();
        ensure!(
            z * self.y == a + challenge.x() * self.x,
            Error::CiphertextRefreshmentFinalResponseVerificationError { check: 1 }
        );
        ensure!(
            z * self.pc_gens.B_blinding == b + challenge.x() * *self.pub_key.pub_key,
            Error::CiphertextRefreshmentFinalResponseVerificationError { check: 2 }
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
    const SEED_2: [u8; 32] = [19u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn test_ciphertext_refreshment_proof() {
        let gens = PedersenGens::default();
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = Scalar::from(13u32);

        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let (_, ciphertext1) = elg_pub.encrypt_value(secret_value, &mut rng);
        let (_, ciphertext2) = elg_pub.encrypt_value(secret_value, &mut rng);

        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            elg_secret,
            ciphertext1,
            ciphertext2,
            &gens,
        );
        let verifier = CipherTextRefreshmentVerifier::new(elg_pub, ciphertext1, ciphertext2, &gens);
        let mut transcript = Transcript::new(CIPHERTEXT_REFRESHMENT_FINAL_RESPONSE_LABEL);

        // Positive tests
        let mut transcript_rng = prover.create_transcript_rng(&mut rng, &transcript);
        let (prover, initial_message) = prover.generate_initial_message(&mut transcript_rng);
        initial_message.update_transcript(&mut transcript).unwrap();
        let challenge = transcript
            .scalar_challenge(CIPHERTEXT_REFRESHMENT_PROOF_CHALLENGE_LABEL)
            .unwrap();
        let final_response = prover.apply_challenge(&challenge);

        let result = verifier.verify(&challenge, &initial_message, &final_response);
        assert!(result.is_ok());

        // Negative tests
        let bad_initial_message = CipherTextRefreshmentInitialMessage::default();
        let result = verifier.verify(&challenge, &bad_initial_message, &final_response);
        assert_err!(
            result,
            Error::CiphertextRefreshmentFinalResponseVerificationError { check: 1 }
        );

        let bad_final_response = CipherTextRefreshmentFinalResponse(Default::default());
        assert_err!(
            verifier.verify(&challenge, &initial_message, &bad_final_response),
            Error::CiphertextRefreshmentFinalResponseVerificationError { check: 1 }
        );
    }

    #[test]
    #[wasm_bindgen_test]
    fn verify_ciphertext_refreshment_method() {
        let mut rng = StdRng::from_seed(SEED_2);
        let gens = PedersenGens::default();
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let (_, cipher) = elg_pub.encrypt_value(3u32.into(), &mut rng);

        let new_rand_blind = Scalar::random(&mut rng);
        let new_cipher = cipher.refresh(&elg_secret, new_rand_blind).unwrap();

        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            elg_secret, cipher, new_cipher, &gens,
        );
        let verifier = CipherTextRefreshmentVerifier::new(elg_pub, cipher, new_cipher, &gens);

        let proof = encryption_proofs::single_property_prover(prover, &mut rng).unwrap();

        assert!(encryption_proofs::single_property_verifier(&verifier, &proof).is_ok());
    }

    #[test]
    #[wasm_bindgen_test]
    fn serialize_deserialize_proof() {
        let mut rng = StdRng::from_seed(SEED_1);
        let secret_value = Scalar::from(13u32);
        let gens = PedersenGens::default();
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();
        let (_, ciphertext1) = elg_pub.encrypt_value(secret_value, &mut rng);
        let (_, ciphertext2) = elg_pub.encrypt_value(secret_value, &mut rng);

        let prover = CipherTextRefreshmentProverAwaitingChallenge::new(
            elg_secret,
            ciphertext1,
            ciphertext2,
            &gens,
        );
        let (initial_message0, final_response0) = encryption_proofs::single_property_prover::<
            StdRng,
            CipherTextRefreshmentProverAwaitingChallenge,
        >(prover, &mut rng)
        .unwrap();

        let init_bytes = initial_message0.encode();
        let mut init_slice = &init_bytes[..];
        let recovered_initial_message =
            <CipherTextRefreshmentInitialMessage>::decode(&mut init_slice).unwrap();
        assert_eq!(recovered_initial_message, initial_message0);

        let final_bytes = final_response0.encode();
        let mut final_slice = &final_bytes[..];
        let recovered_final_response =
            <CipherTextRefreshmentFinalResponse>::decode(&mut final_slice).unwrap();
        assert_eq!(recovered_final_response, final_response0);
    }
}
