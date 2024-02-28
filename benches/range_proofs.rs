use bulletproofs::PedersenGens;
use codec::Encode;
use confidential_assets::{InRangeProof, Scalar, BALANCE_RANGE};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use rand::{rngs::StdRng, SeedableRng};

struct ValueCommitment {
    value: u64,
    blinding: Scalar,
    commitment: CompressedRistretto,
}

fn make_commitment(n: u32, rng: &mut StdRng) -> ValueCommitment {
    let gens = PedersenGens::default();
    let value = 10u64.pow(n);
    let blinding = Scalar::random(rng);
    let commitment = gens.commit(value.into(), blinding).compress();
    ValueCommitment {
        value,
        blinding,
        commitment,
    }
}

fn bench_single_range_proofs(c: &mut Criterion) {
    let mut rng = StdRng::from_seed([42u8; 32]);

    let mut group = c.benchmark_group("range_proofs");

    let gens = PedersenGens::default();
    let init_transcript = Transcript::new(b"BENCH");
    let values = (7..10)
        .into_iter()
        .map(|i| {
            let value = 10u64.pow(i);
            let blinding = Scalar::random(&mut rng);
            (value, blinding)
        })
        .collect::<Vec<_>>();

    for (value, blinding) in &values {
        group.bench_with_input(
            BenchmarkId::new("prove_single", value),
            &value,
            |b, &value| {
                b.iter(|| {
                    let mut transcript = init_transcript.clone();
                    // generate range proof.
                    let _proof = InRangeProof::prove_multiple(
                        &gens,
                        &mut transcript,
                        &[*value],
                        &[*blinding],
                        BALANCE_RANGE,
                        &mut rng,
                    )
                    .expect("Range proof");
                })
            },
        );
    }

    for (value, blinding) in &values {
        let mut transcript = init_transcript.clone();
        let commitment = gens.commit((*value).into(), *blinding).compress();
        // generate range proof.
        let proof = InRangeProof::prove_multiple(
            &gens,
            &mut transcript,
            &[*value],
            &[*blinding],
            BALANCE_RANGE,
            &mut rng,
        )
        .expect("Range proof");
        group.bench_with_input(
            BenchmarkId::new("verify_single", value),
            &proof,
            |b, proof| {
                b.iter(|| {
                    let mut transcript = init_transcript.clone();
                    proof
                        .verify_multiple(
                            &gens,
                            &mut transcript,
                            &[commitment],
                            BALANCE_RANGE,
                            &mut rng,
                        )
                        .expect("valid proof");
                })
            },
        );
    }
    group.finish();
}

fn bench_batch_range_proofs(c: &mut Criterion) {
    const MAX_SIZE: usize = 16;
    let mut rng = StdRng::from_seed([42u8; 32]);

    let mut group = c.benchmark_group("range_proofs batch");

    let gens = PedersenGens::default();
    let init_transcript = Transcript::new(b"BENCH");
    let mut values = Vec::new();
    let mut blindings = Vec::new();
    let mut commitments = Vec::new();
    for i in 0..MAX_SIZE {
        let value = 10u64.pow(i as u32);
        let blinding = Scalar::random(&mut rng);
        let commitment = gens.commit(value.into(), blinding).compress();
        values.push(value);
        blindings.push(blinding);
        commitments.push(commitment);
    }

    for size in [1, 2, 4, 8, 16] {
        group.bench_with_input(BenchmarkId::new("prove_single", size), &size, |b, &size| {
            b.iter(|| {
                let mut transcript = init_transcript.clone();
                // generate range proof.
                for idx in 0..size {
                    let _proof = InRangeProof::prove_multiple(
                        &gens,
                        &mut transcript,
                        &[values[idx]],
                        &[blindings[idx]],
                        BALANCE_RANGE,
                        &mut rng,
                    )
                    .expect("Range proof");
                }
            })
        });
        group.bench_with_input(
            BenchmarkId::new("prove_multiple", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let values = &values.as_slice()[0..size];
                    let blindings = &blindings.as_slice()[0..size];
                    let mut transcript = init_transcript.clone();
                    // generate range proof.
                    let _proof = InRangeProof::prove_multiple(
                        &gens,
                        &mut transcript,
                        values,
                        blindings,
                        BALANCE_RANGE,
                        &mut rng,
                    )
                    .expect("Range proof");
                })
            },
        );
    }

    for size in [1, 2, 4, 8, 16] {
        let mut transcript = init_transcript.clone();
        // generate range proofs.
        let mut proofs = Vec::new();
        let mut enc_len = 0;
        for idx in 0..size {
            let proof = InRangeProof::prove_multiple(
                &gens,
                &mut transcript,
                &[values[idx]],
                &[blindings[idx]],
                BALANCE_RANGE,
                &mut rng,
            )
            .expect("Range proof");
            enc_len += proof.encode().len();
            proofs.push(proof);
        }
        eprintln!("batched singles encode size: batch={size}, enc_len={enc_len}");
        group.bench_with_input(
            BenchmarkId::new("verify_single", size),
            &proofs,
            |b, proofs| {
                b.iter(|| {
                    let mut transcript = init_transcript.clone();
                    for idx in 0..size {
                        proofs[idx]
                            .verify_multiple(
                                &gens,
                                &mut transcript,
                                &[commitments[idx]],
                                BALANCE_RANGE,
                                &mut rng,
                            )
                            .expect("valid proof");
                    }
                })
            },
        );
        let values = &values.as_slice()[0..size];
        let blindings = &blindings.as_slice()[0..size];
        let commitments = &commitments.as_slice()[0..size];
        let mut transcript = init_transcript.clone();
        // generate range proof.
        let proof = InRangeProof::prove_multiple(
            &gens,
            &mut transcript,
            values,
            blindings,
            BALANCE_RANGE,
            &mut rng,
        )
        .expect("Range proof");
        eprintln!(
            "multiple encode size: batch={size}, enc_len={}",
            proof.encode().len()
        );
        group.bench_with_input(
            BenchmarkId::new("verify_multiple", size),
            &proof,
            |b, proof| {
                b.iter(|| {
                    let mut transcript = init_transcript.clone();
                    proof
                        .verify_multiple(
                            &gens,
                            &mut transcript,
                            commitments,
                            BALANCE_RANGE,
                            &mut rng,
                        )
                        .expect("valid proof");
                })
            },
        );
    }
    group.finish();
}

fn bench_asset_range_proofs(c: &mut Criterion) {
    const MAX_SIZE: u32 = 8;
    let mut rng = StdRng::from_seed([42u8; 32]);

    let mut group = c.benchmark_group("range_proofs asset");

    let gens = PedersenGens::default();
    let init_transcript = Transcript::new(b"BENCH");
    let mut assets = Vec::new();
    for i in 0..MAX_SIZE {
        let v1 = make_commitment(i, &mut rng);
        let v2 = make_commitment(i + MAX_SIZE, &mut rng);
        assets.push((v1, v2));
    }

    for size in [1, 2, 4, 8] {
        group.bench_with_input(BenchmarkId::new("prove_single", size), &size, |b, &size| {
            b.iter(|| {
                let mut transcript = init_transcript.clone();
                // generate range proof.
                for idx in 0..size {
                    let asset = &assets[idx];
                    let _proof = InRangeProof::prove_multiple(
                        &gens,
                        &mut transcript,
                        &[asset.0.value, asset.1.value],
                        &[asset.0.blinding, asset.1.blinding],
                        BALANCE_RANGE,
                        &mut rng,
                    )
                    .expect("Range proof");
                }
            })
        });
        group.bench_with_input(
            BenchmarkId::new("prove_multiple", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut values = Vec::with_capacity(size * 2);
                    let mut blindings = Vec::with_capacity(size * 2);
                    for idx in 0..size {
                        let asset = &assets[idx];
                        values.push(asset.0.value);
                        values.push(asset.1.value);
                        blindings.push(asset.0.blinding);
                        blindings.push(asset.1.blinding);
                    }
                    let mut transcript = init_transcript.clone();
                    // generate range proof.
                    let _proof = InRangeProof::prove_multiple(
                        &gens,
                        &mut transcript,
                        values.as_slice(),
                        blindings.as_slice(),
                        BALANCE_RANGE,
                        &mut rng,
                    )
                    .expect("Range proof");
                })
            },
        );
    }

    for size in [1, 2, 4, 8] {
        let mut transcript = init_transcript.clone();
        // generate range proofs.
        let mut proofs = Vec::new();
        let mut enc_len = 0;
        for idx in 0..size {
            let asset = &assets[idx];
            let proof = InRangeProof::prove_multiple(
                &gens,
                &mut transcript,
                &[asset.0.value, asset.1.value],
                &[asset.0.blinding, asset.1.blinding],
                BALANCE_RANGE,
                &mut rng,
            )
            .expect("Range proof");
            enc_len += proof.encode().len();
            proofs.push(proof);
        }
        eprintln!("batched singles encode size: batch={size}, enc_len={enc_len}");
        group.bench_with_input(
            BenchmarkId::new("verify_single", size),
            &proofs,
            |b, proofs| {
                b.iter(|| {
                    let mut transcript = init_transcript.clone();
                    for idx in 0..size {
                        let asset = &assets[idx];
                        proofs[idx]
                            .verify_multiple(
                                &gens,
                                &mut transcript,
                                &[asset.0.commitment, asset.1.commitment],
                                BALANCE_RANGE,
                                &mut rng,
                            )
                            .expect("valid proof");
                    }
                })
            },
        );
        let mut values = Vec::with_capacity(size * 2);
        let mut blindings = Vec::with_capacity(size * 2);
        let mut commitments = Vec::with_capacity(size * 2);
        for idx in 0..size {
            let asset = &assets[idx];
            values.push(asset.0.value);
            values.push(asset.1.value);
            blindings.push(asset.0.blinding);
            blindings.push(asset.1.blinding);
            commitments.push(asset.0.commitment);
            commitments.push(asset.1.commitment);
        }
        let mut transcript = init_transcript.clone();
        // generate range proof.
        let proof = InRangeProof::prove_multiple(
            &gens,
            &mut transcript,
            &values,
            &blindings,
            BALANCE_RANGE,
            &mut rng,
        )
        .expect("Range proof");
        eprintln!(
            "multiple encode size: batch={size}, enc_len={}",
            proof.encode().len()
        );
        group.bench_with_input(
            BenchmarkId::new("verify_multiple", size),
            &proof,
            |b, proof| {
                b.iter(|| {
                    let mut transcript = init_transcript.clone();
                    proof
                        .verify_multiple(
                            &gens,
                            &mut transcript,
                            &commitments,
                            BALANCE_RANGE,
                            &mut rng,
                        )
                        .expect("valid proof");
                })
            },
        );
    }
    group.finish();
}

fn bench_range_proofs(c: &mut Criterion) {
    bench_single_range_proofs(c);
    bench_batch_range_proofs(c);
    bench_asset_range_proofs(c);
}

criterion_group! {
    name = range_proofs;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
    targets = bench_range_proofs,
}

criterion_main!(range_proofs);
