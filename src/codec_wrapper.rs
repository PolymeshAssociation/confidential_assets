use bulletproofs::RangeProof;
use codec::{Compact, CompactLen, Decode, Encode, Error as CodecError, Input, Output};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sp_std::vec::Vec;

/// Constants:
/// A serialized Ristretto point size.
pub const RISTRETTO_POINT_SIZE: usize = 32;

/// A serialized Scalar size.
pub const SCALAR_SIZE: usize = 32;

/// Adds support to `Encode` of SCALE codec to `RistrettoPoint` type.
pub struct RistrettoPointEncoder<'a>(pub &'a RistrettoPoint);

impl<'a> Encode for RistrettoPointEncoder<'a> {
    #[inline]
    fn size_hint(&self) -> usize {
        RISTRETTO_POINT_SIZE
    }

    /// Compresses the `RistrettoPoint` and encodes it as an array of bytes.
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.0.compress().as_bytes().encode_to(dest);
    }
}

/// Adds support to `Decode` of SCALE codec's to `RistrettoPoint` type.
pub struct RistrettoPointDecoder(pub RistrettoPoint);

impl Decode for RistrettoPointDecoder {
    /// Decodes a compressed `RistrettoPoint` from an array of bytes.
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let id = <[u8; RISTRETTO_POINT_SIZE]>::decode(input)?;
        let inner = CompressedRistretto(id)
            .decompress()
            .ok_or_else(|| CodecError::from("Invalid compressed `RistrettoPoint`."))?;

        Ok(Self(inner))
    }
}

/// Adds support to `Encode` of SCALE codec to `CompressedRistretto` type.
pub struct CompressedRistrettoEncoder<'a>(pub &'a CompressedRistretto);

impl<'a> Encode for CompressedRistrettoEncoder<'a> {
    #[inline]
    fn size_hint(&self) -> usize {
        RISTRETTO_POINT_SIZE
    }

    /// Encodes itself as an array of bytes.
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.0.as_bytes().encode_to(dest);
    }
}

/// Adds support to `Decode` of SCALE codec's to `CompressedRistretto` type.
pub struct CompressedRistrettoDecoder(pub CompressedRistretto);

impl Decode for CompressedRistrettoDecoder {
    /// Decodes a `CompressedRistretto` from an array of bytes.
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let id = <[u8; RISTRETTO_POINT_SIZE]>::decode(input)?;
        let inner = CompressedRistretto(id);

        let _ = inner
            .decompress()
            .ok_or_else(|| CodecError::from("Invalid `CompressedRistretto`."))?;

        Ok(Self(inner))
    }
}

/// Adds support to `Encode` of SCALE codec to `Scalar` type.
pub struct ScalarEncoder<'a>(pub &'a Scalar);

impl<'a> Encode for ScalarEncoder<'a> {
    #[inline]
    fn size_hint(&self) -> usize {
        SCALAR_SIZE
    }

    /// Encodes itself as an array of bytes.
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.0.as_bytes().encode_to(dest);
    }
}

/// Adds support to `Decode` of SCALE codec's to `Scalar` type.
pub struct ScalarDecoder(pub Scalar);

impl Decode for ScalarDecoder {
    /// Decodes a `Scalar` from an array of bytes.
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let raw = <[u8; SCALAR_SIZE]>::decode(input)?;
        let inner = Scalar::from_bits(raw);

        Ok(Self(inner))
    }
}

/// Adds support to `Encode` of SCALE codec to `RangeProof` type.
pub struct RangeProofEncoder<'a>(pub &'a RangeProof);

impl<'a> Encode for RangeProofEncoder<'a> {
    fn size_hint(&self) -> usize {
        // See `RangeProof::to_bytes`.
        #[cfg(not(feature = "balance_64"))]
        const LOG_OF_NUM_SECRET_BITS: usize = 5;
        #[cfg(feature = "balance_64")]
        const LOG_OF_NUM_SECRET_BITS: usize = 6;
        const SIZE: usize = (2 * LOG_OF_NUM_SECRET_BITS + 9) * 32;

        Compact::<u32>::compact_len(&(SIZE as u32)) + SIZE
    }

    /// Encodes itself as an array of bytes.
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.0.to_bytes().encode_to(dest);
    }
}

/// Adds support to `Decode` of SCALE codec's to `RangeProofDencoder` type.
pub struct RangeProofDencoder(pub RangeProof);

impl Decode for RangeProofDencoder {
    /// Decodes a `Scalar` from an array of bytes.
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let raw = <Vec<u8>>::decode(input)?;
        let range_proof =
            RangeProof::from_bytes(&raw).map_err(|_| CodecError::from("Invalid `Range_Proof`"))?;

        Ok(Self(range_proof))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proofs::range_proof::InRangeProof;
    use rand::thread_rng;
    use sha3::Sha3_512;

    /// Test encode wrapper `$encoder` and decode wrapper `$decoder` using `data` as input.
    /// The input `data` is a list of tuples, where first element is the object to encode, and the
    /// second is the expected value of the encoded object.
    macro_rules! test_codec_wrapper {
        ($encoder:ident, $decoder:ty, $data:expr) => {
            for (input, expected) in $data.iter() {
                let mut encoded = $encoder(input).encode();
                assert_eq!(encoded, *expected);

                let mut encoded_slice: &[u8] = encoded.as_mut_slice();
                let decoded = <$decoder>::decode(&mut encoded_slice)?;
                assert_eq!(&decoded.0, input);
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

        test_codec_wrapper!(RistrettoPointEncoder, RistrettoPointDecoder, data);

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

        test_codec_wrapper!(CompressedRistrettoEncoder, CompressedRistrettoDecoder, data);
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

        test_codec_wrapper!(ScalarEncoder, ScalarDecoder, data);
        Ok(())
    }

    #[test]
    fn range_proof_codec() -> Result<(), CodecError> {
        let mut rng = thread_rng();

        let proof_1 = InRangeProof::build(&mut rng).response;
        let proof_2 = InRangeProof::build(&mut rng).response;

        assert!(proof_1.to_bytes() != proof_2.to_bytes());

        for input in [proof_1, proof_2].iter() {
            let mut encoded = RangeProofEncoder(input).encode();

            let mut encoded_slice: &[u8] = encoded.as_mut_slice();
            let decoded = RangeProofDencoder::decode(&mut encoded_slice)?;
            assert_eq!(decoded.0.to_bytes(), input.to_bytes());
        }
        Ok(())
    }
}
