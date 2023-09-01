//! Encrypt the same `CommitmentWitness` with multiple keys.

use crate::{
    elgamal::{CommitmentWitness, ElgamalPublicKey},
    codec_wrapper::{
        RistrettoPointDecoder, RistrettoPointEncoder,
    },
    errors::Result,
};

use bulletproofs::PedersenGens;
use curve25519_dalek::{
    ristretto::RistrettoPoint,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use codec::{Decode, Encode, EncodeLike, Error as CodecError, Input, Output};
use sp_std::prelude::*;

/// Encrypt a secret using multiple public keys.
#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CipherTextMultiKey {
    pub x: Vec<RistrettoPoint>,
    pub y: RistrettoPoint,
}

impl Encode for CipherTextMultiKey {
    #[inline]
    fn size_hint(&self) -> usize {
        let x = self.x.iter().map(|x| RistrettoPointEncoder(x)).collect::<Vec<_>>();
        x.size_hint() + RistrettoPointEncoder(&self.y).size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        let x = self.x.iter().map(|x| RistrettoPointEncoder(x)).collect::<Vec<_>>();
        x.encode_to(dest);
        RistrettoPointEncoder(&self.y).encode_to(dest);
    }
}

impl EncodeLike for CipherTextMultiKey {}

impl Decode for CipherTextMultiKey {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let x = <Vec<RistrettoPointDecoder>>::decode(input)?.into_iter().map(|r| r.0).collect();
        let y = <RistrettoPointDecoder>::decode(input)?.0;

        Ok(Self { x, y })
    }
}

impl CipherTextMultiKey {
    pub fn with_witness(
        witness: &CommitmentWitness,
        keys: &[ElgamalPublicKey],
    ) -> Self {
        let x = keys.into_iter().map(|k| witness.blinding * k.pub_key).collect();
        let gens = PedersenGens::default();
        let y = gens.commit(witness.value, witness.blinding);
    
        Self {
          x,
          y,
        }
    }
}

/// Builder for encrypting a secret using multiple public keys.
#[derive(Clone, Debug)]
pub struct CipherTextMultiKeyBuilder {
    witness: CommitmentWitness,
    cipher: CipherTextMultiKey,
}

impl CipherTextMultiKeyBuilder {
    pub fn new(
        witness: &CommitmentWitness,
        keys: &[ElgamalPublicKey],
    ) -> Self {
        let gens = PedersenGens::default();
        let y = gens.commit(witness.value, witness.blinding);
    
        let mut builder = Self {
            witness: witness.clone(),
            cipher: CipherTextMultiKey {
                x: Vec::with_capacity(keys.len()),
                y,
            }
        };
        builder.append_keys(keys);

        builder
    }

    pub fn build(self) -> CipherTextMultiKey {
        self.cipher
    }
}

impl CipherTextMultiKeyBuilder {
    pub fn append_keys(&mut self, keys: &[ElgamalPublicKey]) {
        for key in keys {
            self.append_key(&key);
        }
    }

    pub fn append_key(&mut self, key: &ElgamalPublicKey) {
        self.cipher.x.push(self.witness.blinding() * key.pub_key);
    }
}
