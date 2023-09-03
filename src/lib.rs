//! mercat is the library that implements the confidential transactions
//! of the MERCAT, as defined in the section 6 of the whitepaper.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use zeroize::{Zeroize, ZeroizeOnDrop};

pub use curve25519_dalek::scalar::Scalar;

#[macro_use]
pub(crate) mod macros;

pub mod errors;

pub mod codec_wrapper;
pub mod elgamal;
pub mod proofs;
pub mod transaction;

pub use elgamal::{
    CipherText, CipherTextWithHint, CompressedElgamalPublicKey, ElgamalPublicKey, ElgamalSecretKey,
};
pub use errors::{Error, Result};
pub use proofs::{
    ciphertext_refreshment_proof::CipherEqualSamePubKeyProof, correctness_proof::CorrectnessProof,
    range_proof::InRangeProof,
    wellformedness_proof::WellformednessProof,
};

/// The balance value to keep confidential.
///
/// Since Elgamal decryption involves searching the entire
/// space of possible values. We have limited
/// the size of the balance to 64 bits.
///
/// Possible remedies are:
/// #0 limit the range even further since confidential values
///     in the context of Polymesh could be limited.
/// #1 use AVX2 instruction sets if available on the target
///    architectures. Our preliminary investigation using
///    `curve25519_dalek`'s AVX2 features doesn't show a
///    significant improvment.
/// #2 Given the fact that encrypted Elgamal values are mostly used
///    for zero-knowledge proof generations, it is very likely that
///    we won't need to decrypt the encrypted values very often.
///    We can recommend that applications use a different faster
///    encryption mechanism to store the confidentional values on disk.
pub type Balance = u64;
pub const BALANCE_RANGE: u32 = 64;

// -------------------------------------------------------------------------------------
// -                                 New Type Def                                      -
// -------------------------------------------------------------------------------------

/// Holds ElGamal encryption keys.
#[derive(Clone, Debug)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ElgamalKeys {
    #[zeroize(skip)]
    pub public: ElgamalPublicKey,
    pub secret: ElgamalSecretKey,
}

impl core::ops::Deref for ElgamalKeys {
  type Target = ElgamalSecretKey;
  fn deref(&self) -> &Self::Target {
      &self.secret
  }
}
