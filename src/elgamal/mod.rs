//! The `elgamal_encryption` library implements the
//! twisted-Elgamal encryption over the Ristretto 25519 curve.
//! Since Elgamal is a homomorphic encryption it also provides
//! addition and subtraction API over the cipher texts.

use crate::{
    codec_wrapper::{
        WrappedCompressedRistretto, WrappedRistretto, WrappedScalar, RISTRETTO_POINT_SIZE,
    },
    errors::{Error, Result},
    Balance,
};

use bulletproofs::PedersenGens;
use core::ops::{Add, AddAssign, Deref, Sub, SubAssign};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use codec::{Decode, Encode, Error as CodecError, Input, MaxEncodedLen};
use scale_info::{build::Fields, Path, Type, TypeInfo};

use core::cmp::Ordering;

#[cfg(feature = "sha3")]
pub mod const_time_elgamal_encryption;
#[cfg(feature = "discrete_log")]
pub mod discrete_log;
pub mod multi_key;

/// Prover's representation of the commitment secret.
#[derive(Clone, PartialEq, Zeroize, ZeroizeOnDrop, Debug)]
pub struct CommitmentWitness {
    /// Depending on how the witness was created this variable stores the
    /// balance value or transaction amount in Scalar format.
    value: Scalar,

    /// A random blinding factor.
    blinding: Scalar,
}

impl CommitmentWitness {
    pub fn blinding(&self) -> Scalar {
        self.blinding
    }

    pub fn value(&self) -> Scalar {
        self.value
    }
}

impl CommitmentWitness {
    pub fn new(value: Scalar, blinding: Scalar) -> Self {
        CommitmentWitness { value, blinding }
    }
}

/// Prover's representation of the encrypted secret.
#[derive(Copy, Clone, Encode, Decode, Default, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CipherText {
    pub x: WrappedRistretto,
    pub y: WrappedRistretto,
}

impl TypeInfo for CipherText {
    type Identity = Self;
    fn type_info() -> Type {
        Type::builder()
            .path(Path::new("CipherText", module_path!()))
            .composite(Fields::unnamed().field(|f| {
                f.ty::<[u8; RISTRETTO_POINT_SIZE * 2]>()
                    .type_name("CompressedCipherText")
            }))
    }
}

impl CipherText {
    /// Create a `CipherText` when the `value` isn't secret (asset minting).
    pub fn value(value: Scalar) -> Self {
        let gens = PedersenGens::default();
        Self {
            x: Default::default(),
            y: (value * gens.B).into(),
        }
    }

    /// Create a `CipherText` with zero value and blinding factors.
    ///
    /// Useful for account initialization (zero balance).
    pub fn zero() -> Self {
        Default::default()
    }

    pub fn compress(&self) -> CompressedCipherText {
        CompressedCipherText::from_points(self.x.compress(), self.y.compress())
    }
}

// ------------------------------------------------------------------------
// Arithmetic operations on the ciphertext.
// ------------------------------------------------------------------------

impl<'a, 'b> Add<&'b CipherText> for &'a CipherText {
    type Output = CipherText;

    fn add(self, other: &'b CipherText) -> CipherText {
        CipherText {
            x: (*self.x + *other.x).into(),
            y: (*self.y + *other.y).into(),
        }
    }
}
define_add_variants!(LHS = CipherText, RHS = CipherText, Output = CipherText);

impl<'b> AddAssign<&'b CipherText> for CipherText {
    fn add_assign(&mut self, _rhs: &CipherText) {
        *self = (self as &CipherText) + _rhs;
    }
}
define_add_assign_variants!(LHS = CipherText, RHS = CipherText);

impl<'a, 'b> Sub<&'b CipherText> for &'a CipherText {
    type Output = CipherText;

    fn sub(self, other: &'b CipherText) -> CipherText {
        CipherText {
            x: (*self.x - *other.x).into(),
            y: (*self.y - *other.y).into(),
        }
    }
}
define_sub_variants!(LHS = CipherText, RHS = CipherText, Output = CipherText);

impl<'b> SubAssign<&'b CipherText> for CipherText {
    fn sub_assign(&mut self, _rhs: &CipherText) {
        *self = (self as &CipherText) - _rhs;
    }
}
define_sub_assign_variants!(LHS = CipherText, RHS = CipherText);

/// Compressed `CipherText`.
#[derive(Copy, Clone, TypeInfo, Encode, Debug, PartialEq, Eq)]
pub struct CompressedCipherText([u8; RISTRETTO_POINT_SIZE * 2]);

impl Decode for CompressedCipherText {
    /// Decodes a `CompressedRistretto` from an array of bytes.
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let (x, y) = <(WrappedCompressedRistretto, WrappedCompressedRistretto)>::decode(input)?;
        Ok(Self::from_points(*x, *y))
    }
}

impl Default for CompressedCipherText {
    fn default() -> Self {
        Self([0u8; RISTRETTO_POINT_SIZE * 2])
    }
}

impl From<CipherText> for CompressedCipherText {
    fn from(other: CipherText) -> Self {
        other.compress()
    }
}

impl CompressedCipherText {
    pub fn from_points(x: CompressedRistretto, y: CompressedRistretto) -> Self {
        let mut bytes = [0u8; RISTRETTO_POINT_SIZE * 2];
        bytes[0..32].copy_from_slice(x.as_bytes());
        bytes[32..64].copy_from_slice(y.as_bytes());
        CompressedCipherText(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::from_points(
            CompressedRistretto::from_slice(&bytes[0..32]).unwrap_or_default(),
            CompressedRistretto::from_slice(&bytes[32..64]).unwrap_or_default(),
        )
    }

    pub fn to_bytes(&self) -> [u8; RISTRETTO_POINT_SIZE * 2] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; RISTRETTO_POINT_SIZE * 2] {
        &self.0
    }

    pub fn x(&self) -> WrappedCompressedRistretto {
        CompressedRistretto::from_slice(&self.0[0..32])
            .unwrap_or_default()
            .into()
    }

    pub fn y(&self) -> WrappedCompressedRistretto {
        CompressedRistretto::from_slice(&self.0[32..64])
            .unwrap_or_default()
            .into()
    }

    pub fn decompress(&self) -> CipherText {
        CipherText {
            x: self.x().decompress().into(),
            y: self.y().decompress().into(),
        }
    }
}

// ------------------------------------------------------------------------
// Arithmetic operations on compressed ciphertext.
// ------------------------------------------------------------------------

impl<'a, 'b> Add<&'b CompressedCipherText> for &'a CompressedCipherText {
    type Output = CompressedCipherText;

    fn add(self, other: &'b CompressedCipherText) -> CompressedCipherText {
        (self.decompress() + other.decompress()).into()
    }
}
define_add_variants!(
    LHS = CompressedCipherText,
    RHS = CompressedCipherText,
    Output = CompressedCipherText
);

impl<'b> AddAssign<&'b CompressedCipherText> for CompressedCipherText {
    fn add_assign(&mut self, _rhs: &CompressedCipherText) {
        *self = (self as &CompressedCipherText) + _rhs;
    }
}
define_add_assign_variants!(LHS = CompressedCipherText, RHS = CompressedCipherText);

impl<'a, 'b> Sub<&'b CompressedCipherText> for &'a CompressedCipherText {
    type Output = CompressedCipherText;

    fn sub(self, other: &'b CompressedCipherText) -> CompressedCipherText {
        (self.decompress() - other.decompress()).into()
    }
}
define_sub_variants!(
    LHS = CompressedCipherText,
    RHS = CompressedCipherText,
    Output = CompressedCipherText
);

impl<'b> SubAssign<&'b CompressedCipherText> for CompressedCipherText {
    fn sub_assign(&mut self, _rhs: &CompressedCipherText) {
        *self = (self as &CompressedCipherText) - _rhs;
    }
}
define_sub_assign_variants!(LHS = CompressedCipherText, RHS = CompressedCipherText);

// ------------------------------------------------------------------------
// Elgamal Encryption.
// ------------------------------------------------------------------------

/// Elgamal key pair:
/// secret_key := scalar
/// public_key := secret_key * g
///
/// Encryption:
/// plaintext := (value, blinding_factor)
/// cipher_text := (X, Y)
/// X := blinding_factor * public_key
/// Y := blinding_factor * g + value * h
///
/// Decryption:
/// Given (secret_key, X, Y) find value such that:
/// value * h = Y - X / secret_key
///
/// where g and h are 2 orthogonal generators.

/// An Elgamal Secret Key is a random scalar.
#[derive(Clone, Encode, Decode, Zeroize, ZeroizeOnDrop, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ElgamalSecretKey {
    pub secret: WrappedScalar,
}

impl Deref for ElgamalSecretKey {
    type Target = Scalar;
    fn deref(&self) -> &Self::Target {
        &self.secret
    }
}

impl ElgamalSecretKey {
    pub fn secret(&self) -> Scalar {
        *self.secret
    }
}

/// Compressed ElgamalPublicKey.
#[derive(
    Copy, Clone, Default, Encode, MaxEncodedLen, TypeInfo, PartialOrd, Ord, PartialEq, Eq, Debug,
)]
pub struct CompressedElgamalPublicKey([u8; 32]);

impl CompressedElgamalPublicKey {
    pub fn from_public_key(key: &ElgamalPublicKey) -> Self {
        Self(key.pub_key.compress().to_bytes())
    }

    pub fn into_public_key(&self) -> Option<ElgamalPublicKey> {
        let compressed = CompressedRistretto(self.0);
        compressed.decompress().map(|pub_key| ElgamalPublicKey {
            pub_key: pub_key.into(),
        })
    }
}

impl Decode for CompressedElgamalPublicKey {
    /// Decodes a `CompressedElgamalPublicKey` from an array of bytes.
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let compressed = WrappedCompressedRistretto::decode(input)?;
        Ok(Self(compressed.0))
    }
}

impl From<&ElgamalPublicKey> for CompressedElgamalPublicKey {
    fn from(other: &ElgamalPublicKey) -> Self {
        Self::from_public_key(other)
    }
}

impl From<ElgamalPublicKey> for CompressedElgamalPublicKey {
    fn from(other: ElgamalPublicKey) -> Self {
        Self::from_public_key(&other)
    }
}

/// The Elgamal Public Key is the secret key multiplied by the blinding generator (g).
#[derive(Copy, Clone, Encode, Decode, Default, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ElgamalPublicKey {
    pub pub_key: WrappedRistretto,
}

impl ElgamalPublicKey {
    fn encrypt_helper(&self, value: Scalar, blinding: Scalar) -> CipherText {
        let x = blinding * *self.pub_key;
        let gens = PedersenGens::default();
        let y = gens.commit(value, blinding).into();
        CipherText { x: x.into(), y }
    }

    pub fn encrypt(&self, witness: &CommitmentWitness) -> CipherText {
        self.encrypt_helper(witness.value, witness.blinding)
    }

    /// Generates a blinding factor, and encrypts the value.
    pub fn encrypt_value<R: RngCore + CryptoRng>(
        &self,
        value: Scalar,
        rng: &mut R,
    ) -> (CommitmentWitness, CipherText) {
        let blinding = Scalar::random(rng);
        (
            CommitmentWitness { value, blinding },
            self.encrypt_helper(value, blinding),
        )
    }
}

impl PartialOrd for ElgamalPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ElgamalPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        let l = self.pub_key.compress().to_bytes();
        let r = other.pub_key.compress().to_bytes();
        l.cmp(&r)
    }
}

impl ElgamalSecretKey {
    pub fn new(secret: Scalar) -> Self {
        ElgamalSecretKey {
            secret: secret.into(),
        }
    }

    pub fn get_public_key(&self) -> ElgamalPublicKey {
        let gens = PedersenGens::default();
        ElgamalPublicKey {
            pub_key: (self.secret() * gens.B_blinding).into(),
        }
    }

    /// Decrypt a cipher text that is known to encrypt a Balance.
    #[cfg(not(feature = "discrete_log"))]
    pub fn decrypt(&self, cipher_text: &CipherText) -> Result<Balance> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = *cipher_text.y - self.invert() * *cipher_text.x;
        // Brute force all possible values to find the one that matches value * h.
        let mut result = Scalar::ZERO * gens.B;
        for v in 0..Balance::max_value() {
            if result == value_h {
                return Ok(v);
            }
            result += gens.B;
        }

        Err(Error::CipherTextDecryptionError)
    }

    /// Decrypt a cipher text that is known to encrypt a Balance.
    #[cfg(feature = "discrete_log")]
    pub fn decrypt(&self, cipher_text: &CipherText) -> Result<Balance> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = *cipher_text.y - self.invert() * *cipher_text.x;
        let discrete_log = discrete_log::DiscreteLog::new(gens.B);
        if let Some(v) = discrete_log.decode(value_h) {
            return Ok(v as Balance);
        }

        Err(Error::CipherTextDecryptionError)
    }

    /// Decrypt a cipher text that is known to encrypt a Balance.
    #[cfg(feature = "discrete_log")]
    pub fn decrypt_with_hint(
        &self,
        cipher_text: &CipherText,
        min: Balance,
        max: Balance,
    ) -> Option<Balance> {
        if min > max {
            // Bad range.
            return None;
        }
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = *cipher_text.y - self.invert() * *cipher_text.x;
        let discrete_log = discrete_log::DiscreteLog::new(gens.B);
        let starting_point = value_h - Scalar::from(min) * gens.B;
        discrete_log
            .decode_limit(starting_point, max - min)
            .map(|v| v + min)
    }

    /// Decrypt a cipher text that is known to encrypt a Balance.
    #[cfg(not(feature = "discrete_log"))]
    pub fn decrypt_with_hint(
        &self,
        cipher_text: &CipherText,
        min: Balance,
        max: Balance,
    ) -> Option<Balance> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = *cipher_text.y - self.invert() * *cipher_text.x;
        // Brute force all possible values to find the one that matches value * h.
        let mut result = Scalar::from(min) * gens.B;
        for v in min..max {
            if result == value_h {
                return Some(v);
            }
            result += gens.B;
        }

        None
    }

    /// Decrypt a cipher text that is known to encrypt a Balance.
    #[cfg(all(feature = "rayon", not(feature = "discrete_log")))]
    pub fn decrypt_parallel(&self, cipher_text: &CipherText) -> Result<Balance> {
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicBool, Ordering};

        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key
        let value_h = *cipher_text.y - self.invert() * *cipher_text.x;

        const CHUNK_SIZE: Balance = 64 * 1024; // Needs to be a power of two.
        const CHUNK_COUNT: Balance = Balance::max_value() / CHUNK_SIZE;
        let mut tmp = Scalar::ZERO * gens.B;
        // Search the first chunk.
        for v in 0..CHUNK_SIZE {
            if tmp == value_h {
                return Ok(v);
            }
            tmp += gens.B;
        }

        let found = AtomicBool::new(false);
        let chunk_b = tmp;
        let res = (1..CHUNK_COUNT)
            .into_iter()
            .map(|chunk_idx| {
                let chunk_start = tmp;
                tmp += chunk_b;
                (chunk_idx, chunk_start)
            })
            .par_bridge()
            .find_map_any(|(chunk_idx, mut tmp)| {
                let min = chunk_idx * CHUNK_SIZE;
                let max = min + CHUNK_SIZE;
                for v in min..max {
                    if found.load(Ordering::Relaxed) {
                        return None;
                    }
                    if tmp == value_h {
                        found.store(true, Ordering::Relaxed);
                        return Some(v);
                    }
                    tmp += gens.B;
                }
                None
            });
        if let Some(res) = res {
            return Ok(res);
        }

        Err(Error::CipherTextDecryptionError)
    }

    /// Verifies that a cipher text encrypts the given `value`.
    /// This follows the same logic as decrypt(), except that the `value`
    /// is provided and we don't need to search for it.
    pub fn verify(&self, cipher_text: &CipherText, value: &Scalar) -> Result<()> {
        let gens = PedersenGens::default();
        // value * h = Y - X / secret_key.
        let value_h = *cipher_text.y - self.invert() * *cipher_text.x;
        // Verify that the `value` and see if it matches `value * h`.
        if value * gens.B == value_h {
            return Ok(());
        }

        Err(Error::CipherTextDecryptionError)
    }
}

pub fn encrypt_using_two_pub_keys(
    witness: &CommitmentWitness,
    pub_key1: ElgamalPublicKey,
    pub_key2: ElgamalPublicKey,
) -> (CipherText, CipherText) {
    let x1 = witness.blinding * *pub_key1.pub_key;
    let x2 = witness.blinding * *pub_key2.pub_key;
    let gens = PedersenGens::default();
    let y = gens.commit(witness.value, witness.blinding).into();
    let enc1 = CipherText { x: x1.into(), y };
    let enc2 = CipherText { x: x2.into(), y };

    (enc1, enc2)
}

// ------------------------------------------------------------------------
// CipherText Refreshment Method
// ------------------------------------------------------------------------

impl CipherText {
    pub fn refresh(&self, secret_key: &ElgamalSecretKey, blinding: Scalar) -> Result<CipherText> {
        let value: Scalar = secret_key.decrypt(self)?.into();
        let pub_key = secret_key.get_public_key();
        let new_witness = CommitmentWitness { value, blinding };
        let new_ciphertext = pub_key.encrypt(&new_witness);

        Ok(new_ciphertext)
    }

    pub fn refresh_with_hint(
        &self,
        secret_key: &ElgamalSecretKey,
        blinding: Scalar,
        hint: &Scalar,
    ) -> Result<CipherText> {
        secret_key.verify(self, hint)?;
        let pub_key = secret_key.get_public_key();
        let new_witness = CommitmentWitness {
            value: *hint,
            blinding,
        };
        let new_ciphertext = pub_key.encrypt(&new_witness);

        Ok(new_ciphertext)
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use super::*;
    use crate::Balance;
    use rand::{rngs::StdRng, SeedableRng};
    use wasm_bindgen_test::*;

    const SEED_1: [u8; 32] = [42u8; 32];
    const SEED_2: [u8; 32] = [56u8; 32];

    #[test]
    #[wasm_bindgen_test]
    fn basic_enc_dec() {
        let mut rng = StdRng::from_seed(SEED_1);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();

        // Test encrypting balance.
        let balance: Balance = 256;
        let blinding = Scalar::random(&mut rng);
        let balance_witness = CommitmentWitness {
            value: balance.into(),
            blinding,
        };
        // Test encrypt().
        let cipher = elg_pub.encrypt(&balance_witness);
        let balance1 = elg_secret.decrypt(&cipher).unwrap();
        assert_eq!(balance1, balance);

        // Test encrypt_value().
        let (_, cipher) = elg_pub.encrypt_value(balance_witness.value, &mut rng);
        let balance2 = elg_secret.decrypt(&cipher).unwrap();
        assert_eq!(balance2, balance);
    }

    #[test]
    #[wasm_bindgen_test]
    fn basic_enc_dec_zero_blinding() {
        let mut rng = StdRng::from_seed(SEED_1);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();

        // Test encrypting balance.
        let balance: Balance = 256;
        let blinding = Scalar::ZERO;
        let balance_witness = CommitmentWitness {
            value: balance.into(),
            blinding,
        };
        // Test encrypt().
        let cipher = elg_pub.encrypt(&balance_witness);
        let balance1 = elg_secret.decrypt(&cipher).unwrap();
        assert_eq!(balance1, balance);

        // Test creation of CipherText without using a blinding.
        let cipher2 = CipherText::value(Scalar::from(balance));
        assert_eq!(cipher, cipher2);
        let balance2 = elg_secret.decrypt(&cipher2).unwrap();
        assert_eq!(balance2, balance);
    }

    #[test]
    #[wasm_bindgen_test]
    fn basic_enc_dec_zero_ciphertext() {
        let mut rng = StdRng::from_seed(SEED_1);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));

        let cipher = CipherText::zero();
        // Test decrypting zero.
        let balance = elg_secret.decrypt(&cipher).unwrap();
        assert_eq!(balance, 0);
    }

    #[test]
    #[wasm_bindgen_test]
    fn decrypt_with_hint_test() {
        let mut rng = StdRng::from_seed(SEED_1);
        let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret.get_public_key();

        // Test encrypting balance.
        let balance: Balance = 20_000;
        let blinding = Scalar::random(&mut rng);
        let balance_witness = CommitmentWitness {
            value: balance.into(),
            blinding,
        };
        // Test encrypt().
        let cipher = elg_pub.encrypt(&balance_witness);
        let balance1 = elg_secret
            .decrypt_with_hint(&cipher, 5_000, 25_000)
            .unwrap();
        assert_eq!(balance1, balance);
        // Wrong range.
        let balance1 = elg_secret.decrypt_with_hint(&cipher, 50_000, 65_000);
        eprintln!("-- {balance1:?}");
        assert!(balance1.is_none());

        // Test encrypt_value().
        let (_, cipher) = elg_pub.encrypt_value(balance_witness.value, &mut rng);
        let balance2 = elg_secret
            .decrypt_with_hint(&cipher, 5_000, 25_000)
            .unwrap();
        assert_eq!(balance2, balance);
        // Wrong range.
        let balance2 = elg_secret.decrypt_with_hint(&cipher, 50_000, 65_000);
        assert!(balance2.is_none());
    }

    #[test]
    #[wasm_bindgen_test]
    fn homomorphic_encryption() {
        let v1: Scalar = 623u32.into();
        let v2: Scalar = 456u32.into();
        let mut rng = StdRng::from_seed(SEED_2);
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);

        let elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let elg_pub = elg_secret_key.get_public_key();

        let cipher1 = elg_pub.encrypt(&CommitmentWitness {
            value: v1,
            blinding: r1,
        });
        let cipher2 = elg_pub.encrypt(&CommitmentWitness {
            value: v2,
            blinding: r2,
        });
        let mut cipher12 = elg_pub.encrypt(&CommitmentWitness {
            value: v1 + v2,
            blinding: r1 + r2,
        });
        assert_eq!(cipher1 + cipher2, cipher12);
        cipher12 -= cipher2;
        assert_eq!(cipher1, cipher12);

        cipher12 = elg_pub.encrypt(&CommitmentWitness {
            value: v1 - v2,
            blinding: r1 - r2,
        });
        assert_eq!(cipher1 - cipher2, cipher12);
        cipher12 += cipher2;
        assert_eq!(cipher1, cipher12);
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_two_encryptions() {
        let mut rng = StdRng::from_seed([17u8; 32]);
        let value = 256;
        let blinding = Scalar::random(&mut rng);
        let w = CommitmentWitness {
            value: value.into(),
            blinding,
        };

        let scrt1 = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pblc1 = scrt1.get_public_key();

        let scrt2 = ElgamalSecretKey::new(Scalar::random(&mut rng));
        let pblc2 = scrt2.get_public_key();

        let (cipher1, cipher2) = encrypt_using_two_pub_keys(&w, pblc1, pblc2);
        let msg1 = scrt1.decrypt(&cipher1).unwrap();
        let msg2 = scrt2.decrypt(&cipher2).unwrap();
        assert_eq!(value, msg1);
        assert_eq!(value, msg2);
    }
}
