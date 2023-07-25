//! The discrete log implementation for the twisted ElGamal decryption.
//!
//! Copied from: https://github.com/solana-labs/solana/blob/master/zk-token-sdk/src/encryption/discrete_log.rs
//! and modified to support decrypting values larger then 32bits.
//!

use {
    curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT as G,
        ristretto::RistrettoPoint,
        scalar::Scalar,
        traits::{Identity, IsIdentity},
    },
    itertools::Itertools,
    serde::{Deserialize, Serialize},
    std::collections::HashMap,
};

use crate::Balance;

const TWO16: Balance = 65536; // 2^16
const TWO17: Balance = 131072; // 2^17
const BATCH_SIZE: usize = 32;

/// Type that captures a discrete log challenge.
///
/// The goal of discrete log is to find x such that x * generator = target.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub struct DiscreteLog {
    /// Generator point for discrete log
    pub generator: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Default)]
pub struct DecodePrecomputation(HashMap<[u8; 32], u16>);

/// Builds a HashMap of 2^16 elements
#[allow(dead_code)]
fn decode_u32_precomputation(generator: RistrettoPoint) -> DecodePrecomputation {
    let mut hashmap = HashMap::new();

    let two17_scalar = Scalar::from(TWO17);
    let mut point = RistrettoPoint::identity(); // 0 * G
    let generator = two17_scalar * generator; // 2^17 * G

    // iterator for 2^17*0G , 2^17*1G, 2^17*2G, ...
    for x_hi in 0..TWO16 {
        let key = point.compress().to_bytes();
        hashmap.insert(key, x_hi as u16);
        point += generator;
    }

    DecodePrecomputation(hashmap)
}

lazy_static::lazy_static! {
    /// Pre-computed HashMap needed for decryption. The HashMap is independent of (works for) any key.
    pub static ref DECODE_PRECOMPUTATION_FOR_G: DecodePrecomputation = {
        static DECODE_PRECOMPUTATION_FOR_G_BINCODE: &[u8] =
            include_bytes!("decode_u32_precomputation_for_G.bincode");
        bincode::deserialize(DECODE_PRECOMPUTATION_FOR_G_BINCODE).unwrap_or_default()
    };
    pub static ref G_U32_MAX: RistrettoPoint = {
        G * Scalar::from(u32::MAX)
    };
}

/// Solves the discrete log instance using a 16/16 bit offline/online split
impl DiscreteLog {
    /// Discrete log instance constructor.
    pub fn new(generator: RistrettoPoint) -> Self {
        Self { generator }
    }

    pub fn decode(self, starting_point: RistrettoPoint) -> Option<Balance> {
        self.decode_limit(starting_point, Balance::MAX)
    }

    #[cfg(not(feature = "balance_64"))]
    pub fn decode_limit(self, starting_point: RistrettoPoint, _limit: Balance) -> Option<Balance> {
        self.decode_u32(starting_point)
    }

    #[cfg(all(not(feature = "rayon"), feature = "balance_64"))]
    pub fn decode_limit(
        self,
        mut starting_point: RistrettoPoint,
        limit: Balance,
    ) -> Option<Balance> {
        if let Some(v) = self.decode_u32(starting_point) {
            return Some(v);
        }
        let step: Balance = u32::MAX as Balance;
        let mut offset = 0;
        loop {
            offset += step;
            if offset > limit {
                break;
            }
            starting_point -= *G_U32_MAX;
            if let Some(v) = self.decode_u32(starting_point) {
                return Some(v + offset);
            }
        }
        None
    }

    #[cfg(all(feature = "rayon", feature = "balance_64"))]
    pub fn decode_limit(
        self,
        mut starting_point: RistrettoPoint,
        limit: Balance,
    ) -> Option<Balance> {
        use rayon::prelude::*;

        // Use a single thread to check the first 0-u32::MAX range.
        if let Some(v) = self.decode_u32(starting_point) {
            return Some(v);
        }
        const CHUNK_SIZE: Balance = u32::MAX as Balance;
        const CHUNK_COUNT: Balance = Balance::max_value() / CHUNK_SIZE;
        (1..CHUNK_COUNT)
            .into_iter()
            .map_while(|idx| {
                let offset = idx * CHUNK_SIZE;
                if offset < limit {
                    starting_point -= *G_U32_MAX;
                    Some((offset, starting_point))
                } else {
                    // Returning `None` will stop the search.
                    None
                }
            })
            .par_bridge()
            .find_map_any(|(offset, starting_point)| {
                self.decode_u32(starting_point).map(|v| v + offset)
            })
    }

    /// Solves the discrete log problem under the assumption that the solution
    /// is a positive 32-bit number.
    pub fn decode_u32(&self, target: RistrettoPoint) -> Option<Balance> {
        Self::decode_range(target)
    }

    fn decode_range(mut target: RistrettoPoint) -> Option<Balance> {
        let hashmap = &DECODE_PRECOMPUTATION_FOR_G;
        let mut offset = 0;
        let mut batch_points = Vec::with_capacity(BATCH_SIZE);

        for batch in &(0..TWO16).into_iter().chunks(BATCH_SIZE) {
            // batch compression currently errors if any point in the batch is the identity point
            batch_points.clear();
            for idx in batch {
                let point = target;
                target += -G;
                if point.is_identity() {
                    return Some(idx as Balance);
                }
                batch_points.push(point);
            }

            let batch_compressed = RistrettoPoint::double_and_compress_batch(&batch_points);

            for (x_lo, point) in batch_compressed.iter().enumerate() {
                let key = point.to_bytes();
                if hashmap.0.contains_key(&key) {
                    let x_hi = hashmap.0[&key];
                    return Some(offset + x_lo as Balance + TWO16 * x_hi as Balance);
                }
            }
            offset += BATCH_SIZE as Balance;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use {super::*, std::time::Instant};

    #[test]
    #[allow(non_snake_case)]
    fn test_serialize_decode_u32_precomputation_for_G() {
        let decode_u32_precomputation_for_G = decode_u32_precomputation(G);
        // let decode_u32_precomputation_for_G = decode_u32_precomputation(G);

        if decode_u32_precomputation_for_G.0 != DECODE_PRECOMPUTATION_FOR_G.0 {
            use std::{fs::File, io::Write, path::PathBuf};
            let mut f = File::create(PathBuf::from(
                "src/encryption/decode_u32_precomputation_for_G.bincode",
            ))
            .unwrap();
            f.write_all(&bincode::serialize(&decode_u32_precomputation_for_G).unwrap())
                .unwrap();
            panic!("Rebuild and run this test again");
        }
    }

    #[test]
    fn test_decode_correctness() {
        // general case
        let amount: Balance = 4294967295;

        let instance = DiscreteLog::new(G);
        let target = Scalar::from(amount) * G;

        // Very informal measurements for now
        let start_computation = Instant::now();
        let decoded = instance.decode_u32(target);
        let computation_secs = start_computation.elapsed().as_secs_f64();

        assert_eq!(amount, decoded.unwrap());

        println!("single thread discrete log computation secs: {computation_secs:?} sec");
    }
}
