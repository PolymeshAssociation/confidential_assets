use codec::{Compact, CompactLen, Decode, Encode, Error as CodecError, Input, Output};
use bulletproofs::RangeProof;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use core::ops::{
    Deref, DerefMut,
};

use crate::InRangeProof;

/// Constants:
/// A serialized Ristretto point size.
pub const RISTRETTO_POINT_SIZE: usize = 32;

/// A serialized Scalar size.
pub const SCALAR_SIZE: usize = 32;

/// Wrapper for `RistrettoPoint` to implement SCALE encoding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WrappedRistretto(RistrettoPoint);

impl Encode for WrappedRistretto {
    #[inline]
    fn size_hint(&self) -> usize {
        RISTRETTO_POINT_SIZE
    }

    /// Encodes itself as an array of bytes.
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.0.compress().as_bytes().encode_to(dest);
    }
}

impl Decode for WrappedRistretto {
    /// Decodes a `Ristretto` from an array of bytes.
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let id = <[u8; RISTRETTO_POINT_SIZE]>::decode(input)?;
        let compressed = CompressedRistretto(id);

        let inner = compressed
            .decompress()
            .ok_or_else(|| CodecError::from("Invalid `CompressedRistretto`."))?;

        Ok(Self(inner))
    }
}

impl From<WrappedRistretto> for RistrettoPoint {
    fn from(data: WrappedRistretto) -> Self {
        data.0
    }
}

impl Deref for WrappedRistretto {
    type Target = RistrettoPoint;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for WrappedRistretto {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<RistrettoPoint> for WrappedRistretto {
    fn from(data: RistrettoPoint) -> Self {
        Self(data)
    }
}

/// Wrapper for `CompressedRistretto` to implement SCALE encoding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WrappedCompressedRistretto(CompressedRistretto);

impl Encode for WrappedCompressedRistretto {
    #[inline]
    fn size_hint(&self) -> usize {
        RISTRETTO_POINT_SIZE
    }

    /// Encodes itself as an array of bytes.
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.0.as_bytes().encode_to(dest);
    }
}

impl Decode for WrappedCompressedRistretto {
    /// Decodes a `CompressedRistretto` from an array of bytes.
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let id = <[u8; RISTRETTO_POINT_SIZE]>::decode(input)?;
        let inner = CompressedRistretto(id);

        // Ensure the it is a valid RistrettoPoint.
        inner
            .decompress()
            .ok_or_else(|| CodecError::from("Invalid `CompressedRistretto`."))?;

        Ok(Self(inner))
    }
}

impl From<WrappedCompressedRistretto> for RistrettoPoint {
    fn from(data: WrappedCompressedRistretto) -> Self {
        data.decompress()
    }
}

impl Deref for WrappedCompressedRistretto {
    type Target = CompressedRistretto;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for WrappedCompressedRistretto {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<RistrettoPoint> for WrappedCompressedRistretto {
    fn from(data: RistrettoPoint) -> Self {
        Self(data.compress())
    }
}

impl From<CompressedRistretto> for WrappedCompressedRistretto {
    fn from(data: CompressedRistretto) -> Self {
        Self(data)
    }
}

impl WrappedCompressedRistretto {
    pub fn decompress(&self) -> RistrettoPoint {
        // The compressed RistrettoPoint is valided in the SCALE `decode` method.
        self.0.decompress().unwrap_or_default()
    }

    pub fn compress(&self) -> CompressedRistretto {
        self.0
    }
}

/// Wrapper for Scalar to implement SCALE encoding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WrappedScalar(pub Scalar);

impl Encode for WrappedScalar {
    #[inline]
    fn size_hint(&self) -> usize {
        RISTRETTO_POINT_SIZE
    }

    /// Encodes itself as an array of bytes.
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.0.as_bytes().encode_to(dest);
    }
}

impl Decode for WrappedScalar {
    /// Decodes a `Scalar` from an array of bytes.
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let s = <[u8; SCALAR_SIZE]>::decode(input)?;

        let inner = Scalar::from_canonical_bytes(s)
            .ok_or_else(|| CodecError::from("Non-canonical `Scalar`."))?;
        Ok(Self(inner))
    }
}

impl From<WrappedScalar> for Scalar {
    fn from(data: WrappedScalar) -> Self {
        data.0
    }
}

impl Deref for WrappedScalar {
    type Target = Scalar;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for WrappedScalar {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Scalar> for WrappedScalar {
    fn from(data: Scalar) -> Self {
        Self(data)
    }
}

// RangeProof encoding.

impl Encode for InRangeProof {
    fn size_hint(&self) -> usize {
        // See `RangeProof::to_bytes`.
        const LOG_OF_NUM_SECRET_BITS: usize = 6;
        const SIZE: usize = (2 * LOG_OF_NUM_SECRET_BITS + 9) * 32;

        Compact::<u32>::compact_len(&(SIZE as u32)) + SIZE
    }

    /// Encodes itself as an array of bytes.
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.0.to_bytes().encode_to(dest);
    }
}

impl Decode for InRangeProof {
    /// Decodes a `Scalar` from an array of bytes.
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let raw = <Vec<u8>>::decode(input)?;
        let range_proof =
            RangeProof::from_bytes(&raw).map_err(|_| CodecError::from("Invalid `RangeProof`"))?;

        Ok(Self(range_proof))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proofs::range_proof::InRangeProof;
    use rand::thread_rng;
    use sha3::Sha3_512;

    /// Test encode wrapper `$wrapper` using `data` as input.
    /// The input `data` is a list of tuples, where first element is the object to encode, and the
    /// second is the expected value of the encoded object.
    macro_rules! test_codec_wrapper {
        ($wrapper:ident, $data:expr) => {
            for (input, expected) in $data.into_iter() {
                let wrapped: $wrapper = input.into();
                let mut encoded = wrapped.encode();
                assert_eq!(encoded, *expected);

                let mut encoded_slice: &[u8] = encoded.as_mut_slice();
                let decoded = <$wrapper>::decode(&mut encoded_slice)?;
                assert_eq!(decoded, wrapped);
            }
        };
    }

    #[test]
    fn ristretto_codec() -> Result<(), CodecError> {
        let data = [
            (
                RistrettoPoint::hash_from_bytes::<Sha3_512>(b"P1"),
                hex::decode("3ebba85e847bba52901ca771318a16890f276e5d42591d7cae3b291c92601112")
                    .unwrap(),
            ),
            (
                RistrettoPoint::hash_from_bytes::<Sha3_512>(b"P2"),
                hex::decode("8cb1a8d82d8dce6bb9fc32a83a42a0dc6baaab4aeecd2ed6dee4229b5d2c5054")
                    .unwrap(),
            ),
        ];

        test_codec_wrapper!(WrappedRistretto, data);

        Ok(())
    }

    #[test]
    fn compressed_ristretto_codec() -> Result<(), CodecError> {
        let data = [
            (
                RistrettoPoint::hash_from_bytes::<Sha3_512>(b"P1").compress(),
                hex::decode("3ebba85e847bba52901ca771318a16890f276e5d42591d7cae3b291c92601112")
                    .unwrap(),
            ),
            (
                RistrettoPoint::hash_from_bytes::<Sha3_512>(b"P2").compress(),
                hex::decode("8cb1a8d82d8dce6bb9fc32a83a42a0dc6baaab4aeecd2ed6dee4229b5d2c5054")
                    .unwrap(),
            ),
        ];

        test_codec_wrapper!(WrappedCompressedRistretto, data);
        Ok(())
    }

    #[test]
    fn scalar_codec() -> Result<(), CodecError> {
        let data = [
            (
                Scalar::hash_from_bytes::<Sha3_512>(b"S1"),
                hex::decode("b34c1fd5c8fdf7397a403a4894c8b4bc31db8c3b396a6e8cf7d5f13ec1f97500")
                    .unwrap(),
            ),
            (
                Scalar::hash_from_bytes::<Sha3_512>(b"S2"),
                hex::decode("6a063cf39fb556592f9b5febf07bb5cdacbf997c6a35335a8a6a4b99e1a74d08")
                    .unwrap(),
            ),
        ];

        test_codec_wrapper!(WrappedScalar, data);
        Ok(())
    }

    #[test]
    fn range_proof_codec() -> Result<(), CodecError> {
        let mut rng = thread_rng();

        let proof_1 = InRangeProof::build(&mut rng);
        let proof_2 = InRangeProof::build(&mut rng);

        assert!(proof_1.0.to_bytes() != proof_2.0.to_bytes());

        for input in [proof_1, proof_2].iter() {
            let mut encoded = input.encode();

            let mut encoded_slice: &[u8] = encoded.as_mut_slice();
            let decoded = InRangeProof::decode(&mut encoded_slice)?;
            assert_eq!(decoded.0.to_bytes(), input.0.to_bytes());
        }
        Ok(())
    }
}
