//! The `const_time_elgamal_encryption` library implements the
//! Constant Time Elgamal encryption over the Ristretto 25519 curve.
//!
//! Here's a brief overview of this scheme:
//! Elgamal key pair:
//! secret_key := scalar
//! public_key := secret_key * g
//!
//! Constant time encryption:
//! plaintext := (`value`, random_1, random_2)
//! cipher_text := (X, Y, Z)
//! X := random_1 * public_key
//! Y := random_1 * g + random_2 * h
//! Make a one-time-pad from Hash(random_2 * h) and use it to encrypt the `value`:
//! Z := Hash(random_2 * h) ^ value
//!
//! Decryption:
//! Given (secret_key, X, Y, Z) find `value` such that:
//! random_2 * h := Y - X / secret_key
//! Calculate the one-time-pad with Hash(random_2 * h) and use it to decrypt the
//! `value`:
//! decrypted_value := Hash(random_2 * h) ^ Z
//!
//! Where g and h are 2 orthogonal generators.
//! In this implementation, we set `random_1` to the blinding factor used for the
//! twisted Elgamal encryption. This way the twisted Elgamal and regular Elgamal
//! ciphertexts can share the same `X`.
use bulletproofs::PedersenGens;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};

use codec::{Decode, Encode};
use sha3::{digest::FixedOutput, Digest, Sha3_256};

use crate::{
    codec_wrapper::WrappedCompressedRistretto,
    elgamal::{CipherText, CommitmentWitness, ElgamalPublicKey, ElgamalSecretKey},
    errors::Result,
    Balance,
};

#[derive(PartialEq, Copy, Clone, Encode, Decode, Default, Debug)]
pub struct CipherTextHint {
    y: WrappedCompressedRistretto,
    z: [u8; 32],
}

impl CipherTextHint {
    pub fn new<R: RngCore + CryptoRng>(witness: &CommitmentWitness, rng: &mut R) -> Self {
        // Twisted Elgamal encryption.
        let r1 = witness.blinding();

        // Constant Time Elgamal encryption.
        let message_bytes: [u8; 32] = witness.value().to_bytes();
        let r2 = Scalar::random(rng);
        let gens = PedersenGens::default();
        let r2h = r2 * gens.B;

        let y = gens.commit(r2, r1).into(); // r1 * g + r2 * h
        let z = xor_with_one_time_pad(r2h, &message_bytes);

        Self { y, z }
    }

    /// Decrypt the value hint.
    ///
    /// `x` - `ciphertext.x / secret_key`
    pub fn decrypt(&self, x: RistrettoPoint) -> u64 {
        // random_2 * h = Y - X / secret_key
        let random_2_h = self.y.decompress() - x;

        use byteorder::{ByteOrder, LittleEndian};

        let decrypted_msg = xor_with_one_time_pad(random_2_h, &self.z);
        LittleEndian::read_u64(&decrypted_msg)
    }

    pub fn ciphertext_with_hint(&self, cipher: CipherText) -> CipherTextWithHint {
        CipherTextWithHint {
            cipher,
            hint: *self,
        }
    }
}

/// This data structure wraps a twisted Elgamal cipher text with the
/// regular Elgamal cipher text.
/// Since regular Elgamal decryption is constant time, its result is
/// used as a hint to verify the twisted elgamal encryption.
/// Note that we can not only rely on regular Elgamal encryption since
/// 1. it is not homomorphic. 2. all asset proofs prove properties of
/// a twisted Elgamal cipher text.
#[derive(PartialEq, Copy, Clone, Encode, Decode, Default, Debug)]
pub struct CipherTextWithHint {
    // The twisted Elgamal cipher text.
    cipher: CipherText,

    hint: CipherTextHint,
}

impl CipherTextWithHint {
    pub fn ciphertext(&self) -> &CipherText {
        &self.cipher
    }
}

// ------------------------------------------------------------------------
// Constant Time Elgamal Encryption
// ------------------------------------------------------------------------

// Generate a one-time-pad from Hash(key) and byte-wise xor it with the data.
fn xor_with_one_time_pad(key: RistrettoPoint, data: &[u8; 32]) -> [u8; 32] {
    let key_bytes: [u8; 32] = key.compress().to_bytes();
    let hashed_key = Sha3_256::default().chain(key_bytes).finalize_fixed();

    let mut result = [0u8; 32];
    for index in 0..32 {
        result[index] = hashed_key[index] ^ data[index];
    }

    result
}

impl ElgamalPublicKey {
    pub fn const_time_encrypt<R: RngCore + CryptoRng>(
        &self,
        witness: &CommitmentWitness,
        rng: &mut R,
    ) -> CipherTextWithHint {
        CipherTextWithHint {
            cipher: self.encrypt(witness),
            hint: CipherTextHint::new(witness, rng),
        }
    }

    pub fn const_time_encrypt_value<R: RngCore + CryptoRng>(
        &self,
        value: Scalar,
        rng: &mut R,
    ) -> (CommitmentWitness, CipherTextWithHint) {
        let blinding = Scalar::random(rng);
        let witness = CommitmentWitness::new(value, blinding);
        let encrypted_witness = self.const_time_encrypt(&witness, rng);
        (witness, encrypted_witness)
    }
}

impl ElgamalSecretKey {
    /// Decrypt a cipher text that is known to encrypt a `Balance`.
    pub fn const_time_decrypt(&self, cipher_text: &CipherTextWithHint) -> Result<Balance> {
        let decrypted_value = cipher_text
            .hint
            .decrypt(self.invert() * *cipher_text.cipher.x);

        // Verify that the same value was encrypted using twisted Elgamal encryption.
        self.verify(&cipher_text.cipher, &decrypted_value.into())?;
        Ok(decrypted_value)
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::errors::Error;
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    #[test]
    #[wasm_bindgen_test]
    fn basic_const_time_elgamal_enc_dec() {
        let mut rng = StdRng::from_seed([42u8; 32]);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();

        // Test encrypt().
        let values = vec![0 as Balance, 1 as Balance, 255 as Balance, Balance::MAX];
        let _ = values.iter().map(|v| {
            let (_, cipher) = elg_pub.const_time_encrypt_value(Scalar::from(*v), &mut rng);
            let decrypted_v = elg_secret.const_time_decrypt(&cipher).unwrap();
            assert_eq!(decrypted_v, *v);
        });

        // Negative test.
        // If the message is altered, it won't decrypt.
        let value = 111u32;
        let (_, cipher) = elg_pub.const_time_encrypt_value(value.into(), &mut rng);
        let mut corrupt_cipher = cipher;
        corrupt_cipher.hint.z[0] += 1;
        assert_err!(
            elg_secret.const_time_decrypt(&corrupt_cipher),
            Error::CipherTextDecryptionError
        );
    }
}
