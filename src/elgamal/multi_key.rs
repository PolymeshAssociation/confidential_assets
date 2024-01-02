//! Encrypt the same `CommitmentWitness` with multiple keys.

use crate::{
    codec_wrapper::WrappedCompressedRistretto,
    elgamal::{CipherText, CommitmentWitness, ElgamalPublicKey},
};

use bulletproofs::PedersenGens;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Decode, Encode};

/// Encrypt a secret using multiple public keys.
#[derive(Clone, Encode, Decode, Default, Debug, PartialEq, Eq)]
pub struct CipherTextMultiKey {
    pub x: Vec<WrappedCompressedRistretto>,
    pub y: WrappedCompressedRistretto,
}

impl CipherTextMultiKey {
    pub fn with_witness(witness: &CommitmentWitness, keys: &[ElgamalPublicKey]) -> Self {
        let x = keys
            .into_iter()
            .map(|k| (witness.blinding * *k.pub_key).into())
            .collect();
        let gens = PedersenGens::default();
        let y = gens.commit(witness.value, witness.blinding).into();

        Self { x, y }
    }

    /// Convert to a list of `CipherText`.
    pub fn ciphertexts(&self) -> Vec<CipherText> {
        let y = self.y.decompress();
        self.x
            .iter()
            .map(|x| CipherText {
                x: x.decompress().into(),
                y: y.into(),
            })
            .collect()
    }

    /// Get one CipherText.
    pub fn get(&self, idx: usize) -> Option<CipherText> {
        let y = self.y.decompress();
        self.x.get(idx).map(|x| CipherText {
            x: x.decompress().into(),
            y: y.into(),
        })
    }

    /// Returns the number of keys used to encrypt the value.
    pub fn len(&self) -> usize {
        self.x.len()
    }
}

/// Builder for encrypting a secret using multiple public keys.
#[derive(Clone, Debug)]
pub struct CipherTextMultiKeyBuilder {
    witness: CommitmentWitness,
    cipher: CipherTextMultiKey,
}

impl CipherTextMultiKeyBuilder {
    pub fn new<'a>(
        witness: &CommitmentWitness,
        keys: impl Iterator<Item = &'a ElgamalPublicKey>,
    ) -> Self {
        let gens = PedersenGens::default();
        let y = gens.commit(witness.value, witness.blinding).into();

        let mut builder = Self {
            witness: witness.clone(),
            cipher: CipherTextMultiKey { x: Vec::new(), y },
        };
        builder.append_keys(keys);

        builder
    }

    pub fn build(self) -> CipherTextMultiKey {
        self.cipher
    }
}

impl CipherTextMultiKeyBuilder {
    pub fn append_keys<'a>(&mut self, keys: impl Iterator<Item = &'a ElgamalPublicKey>) {
        for key in keys {
            self.append_key(&key);
        }
    }

    pub fn append_key(&mut self, key: &ElgamalPublicKey) {
        self.cipher
            .x
            .push((self.witness.blinding() * *key.pub_key).into());
    }
}
