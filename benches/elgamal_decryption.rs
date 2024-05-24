use std::convert::TryFrom;

use codec::{Decode, Encode};
use confidential_assets::{Balance, CipherText, ElgamalSecretKey, Scalar};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use rand::{rngs::StdRng, SeedableRng};

fn bench_elgamal(c: &mut Criterion) {
    let mut rng = StdRng::from_seed([42u8; 32]);

    let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let elg_pub = elg_secret.get_public_key();

    let mut group = c.benchmark_group("elgamal");

    for i in 0..10 {
        let value = 10u32.pow(i);
        group.bench_with_input(BenchmarkId::new("encrypt", value), &value, |b, &value| {
            b.iter(|| elg_pub.encrypt_value(value.into(), &mut rng))
        });
    }

    let init_value = (10 as Balance).pow(11);
    let (_, enc_init_value) = elg_pub.encrypt_value(init_value.into(), &mut rng);
    for i in 8..10 {
        let value = (10 as Balance).pow(i);
        let (_, enc_value) = elg_pub.encrypt_value(value.into(), &mut rng);
        let enc_result = enc_init_value + enc_value;
        group.bench_with_input(
            BenchmarkId::new("add", value),
            &enc_value,
            |b, enc_value| {
                b.iter(|| {
                    let result = enc_init_value + enc_value;
                    assert_eq!(enc_result, result);
                })
            },
        );
    }
    for i in 8..10 {
        let value = (10 as Balance).pow(i);
        let (_, enc_value) = elg_pub.encrypt_value(value.into(), &mut rng);
        let enc_result = enc_init_value - enc_value;
        group.bench_with_input(
            BenchmarkId::new("sub", value),
            &enc_value,
            |b, enc_value| {
                b.iter(|| {
                    let result = enc_init_value - enc_value;
                    assert_eq!(enc_result, result);
                })
            },
        );
    }

    // Decode + Elgamal add + Encode.
    for i in 8..10 {
        let value = (10 as Balance).pow(i);
        let (_, enc_value) = elg_pub.encrypt_value(value.into(), &mut rng);
        let enc_result = (enc_init_value + enc_value).encode();
        let enc_value = enc_value.encode();
        group.bench_with_input(
            BenchmarkId::new("decode_add_encode", value),
            &enc_value,
            |b, enc_value| {
                b.iter(|| {
                    let enc_value = CipherText::decode(&mut &enc_value[..]).expect("CipherText");
                    let result = (enc_init_value + enc_value).encode();
                    assert_eq!(enc_result, result);
                })
            },
        );
    }
    // Compressed Elgamal math
    for i in 8..10 {
        let value = (10 as Balance).pow(i);
        let (_, enc_value) = elg_pub.encrypt_value(value.into(), &mut rng);
        let enc_result = (enc_init_value + enc_value).compress();
        let enc_init_value = enc_init_value.compress();
        let enc_value = enc_value.compress();
        group.bench_with_input(
            BenchmarkId::new("compressed_add", value),
            &enc_value,
            |b, enc_value| {
                b.iter(|| {
                    let result = enc_init_value + enc_value;
                    assert_eq!(enc_result, result);
                })
            },
        );
    }
    for i in 8..10 {
        let value = (10 as Balance).pow(i);
        let (_, enc_value) = elg_pub.encrypt_value(value.into(), &mut rng);
        let enc_result = (enc_init_value - enc_value).compress();
        let enc_init_value = enc_init_value.compress();
        let enc_value = enc_value.compress();
        group.bench_with_input(
            BenchmarkId::new("compressed_sub", value),
            &enc_value,
            |b, enc_value| {
                b.iter(|| {
                    let result = enc_init_value - enc_value;
                    assert_eq!(enc_result, result);
                })
            },
        );
    }

    #[cfg(not(feature = "discrete_log"))]
    for i in 3..8 {
        let value = (10 as Balance).pow(i);
        let enc_value = elg_pub.encrypt_value(value.into(), &mut rng).1;
        group.bench_with_input(
            BenchmarkId::new("decrypt", value),
            &enc_value,
            |b, enc_value| {
                b.iter(|| {
                    assert_eq!(value, elg_secret.decrypt(enc_value).unwrap());
                })
            },
        );
    }

    #[cfg(feature = "discrete_log")]
    for i in 3..8 {
        let value = (10 as Balance).pow(i);
        let enc_value = elg_pub.encrypt_value(value.into(), &mut rng).1;
        group.bench_with_input(
            BenchmarkId::new("decrypt_discrete_log", value),
            &enc_value,
            |b, enc_value| {
                b.iter(|| {
                    assert_eq!(value, elg_secret.decrypt(enc_value).unwrap());
                })
            },
        );
    }
    #[cfg(all(feature = "rayon", not(feature = "discrete_log")))]
    for i in 3..8 {
        let value = (10 as Balance).pow(i);
        let enc_value = elg_pub.encrypt_value(value.into(), &mut rng).1;
        group.bench_with_input(
            BenchmarkId::new("decrypt_parallel", value),
            &enc_value,
            |b, enc_value| {
                b.iter(|| {
                    assert_eq!(value, elg_secret.decrypt_parallel(enc_value).unwrap());
                })
            },
        );
    }
    let values: Vec<_> = vec![
        (0u64, "0"),
        (1u64, "1"),
        (10u64, "10"),
        (100u64, "100"),
        (1_000u64, "1,000"),
        (10_000u64, "10,000"),
        (65_535u64, "65,535"),
        (65_536u64, "65,536"),
        (65_537u64, "65,537"),
        (100_000u64, "100,000"),
        (131_070u64, "131,070"),
        (131_072u64, "131,072"),
        (1_000_000u64, "1,000,000"),
        (10_000_000u64, "10,000,000"),
        (100_000_000u64, "100,000,000"),
        (1_000_000_000u64, "1,000,000,000"),
        (10_000_000_000u64, "10,000,000,000"),
        (100_000_000_000u64, "100,000,000,000"),
        (1_000_000_000_000u64, "1,000,000,000,000"),
        (10_000_000_000_000u64, "10,000,000,000,000"),
        (100_000_000_000_000u64, "100,000,000,000,000"),
    ]
    .into_iter()
    .filter_map(|(value, s_value)| match Balance::try_from(value).ok() {
        Some(value) => {
            let enc_value = elg_pub.encrypt_value(value.into(), &mut rng).1;
            Some((value, enc_value, format!("{:>19}", s_value)))
        }
        _ => None,
    })
    .collect();
    #[cfg(not(feature = "discrete_log"))]
    {
        for (value, enc_value, s_value) in &values {
            let now = std::time::Instant::now();
            print!("--- time to decrypt simple       {}: ", s_value);
            assert_eq!(*value, elg_secret.decrypt(&enc_value).unwrap());
            let secs = now.elapsed().as_secs_f32();
            println!("{:.3?} secs", secs);
            // Stop if elapsed time above 1 second.
            if secs > 1.0 {
                break;
            }
        }
    }
    #[cfg(all(feature = "rayon", not(feature = "discrete_log")))]
    {
        for (value, enc_value, s_value) in &values {
            let now = std::time::Instant::now();
            print!("--- time to decrypt_simple_par   {}: ", s_value);
            assert_eq!(*value, elg_secret.decrypt_parallel(&enc_value).unwrap());
            let secs = now.elapsed().as_secs_f32();
            println!("{:.3?} secs", secs);
            // Stop if elapsed time above 1 second.
            if secs > 1.0 {
                break;
            }
        }
    }
    #[cfg(feature = "discrete_log")]
    {
        for (value, enc_value, s_value) in &values {
            let now = std::time::Instant::now();
            print!("--- time to decrypt_discrete_log {}: ", s_value);
            assert_eq!(*value, elg_secret.decrypt(&enc_value).unwrap());
            let secs = now.elapsed().as_secs_f32();
            println!("{:.3?} secs", secs);
            // Stop if elapsed time above 1 second.
            if secs > 1.0 {
                break;
            }
        }
    }
    group.finish();
}

criterion_group! {
    name = elgamal_decryption;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
    targets = bench_elgamal,
}

criterion_main!(elgamal_decryption);
