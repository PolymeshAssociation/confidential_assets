use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use codec::Encode;
use confidential_assets::{
    elgamal::CipherText,
    testing::{self, TestSenderProofGen},
    transaction::{ConfidentialTransferProof, MAX_AUDITORS},
    Balance, ElgamalKeys, ElgamalPublicKey,
};
use rand::thread_rng;
use std::collections::BTreeSet;

// The sender's initial balance. Will be in:
// [10^MIN_SENDER_BALANCE_ORDER, 10^(MIN_SENDER_BALANCE_ORDER+1), ..., 10^MAX_SENDER_BALANCE_ORDER]
// The transferred amout on each iteration will be all the balance the sender has: 10^SENDER_BALANCE_ORDER
pub const MIN_SENDER_BALANCE_ORDER: u32 = 10;
pub const MAX_SENDER_BALANCE_ORDER: u32 = 20;

// The receiver's initial balance.
const RECEIVER_INIT_BALANCE: Balance = 10000;

fn bench_transaction_sender_proof_stage(
    c: &mut Criterion,
    sender_account: ElgamalKeys,
    sender_balances: &[(Balance, CipherText)],
    rcvr_pub_account: ElgamalPublicKey,
    auditor_keys: &BTreeSet<ElgamalPublicKey>,
    bench_stage: u32,
) {
    let mut rng = thread_rng();

    let proof_gens: Vec<_> = sender_balances
        .into_iter()
        .map(|(amount, sender_balance)| {
            let mut proof_gen = TestSenderProofGen::new(
                &sender_account,
                sender_balance,
                *amount,
                &rcvr_pub_account,
                auditor_keys,
                *amount,
                &mut rng,
            );
            if bench_stage > 1 {
                proof_gen
                    .run_to_stage(bench_stage - 1, &mut rng)
                    .expect("Stages run ok");
            }

            proof_gen
        })
        .collect();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for proof_gen in &proof_gens {
        group.bench_with_input(
            BenchmarkId::new(
                format!("Sender Proof Stage {bench_stage}"),
                proof_gen.amount,
            ),
            proof_gen,
            |b, proof_gen: &TestSenderProofGen| {
                b.iter(|| {
                    let mut gen = proof_gen.clone();
                    gen.run_to_stage(bench_stage, &mut rng).expect("Stage ok");
                    gen
                })
            },
        );
    }
    group.finish();

    for proof_gen in proof_gens {
        let sender_account = proof_gen.sender_pub;
        let amount = proof_gen.amount;
        let sender_init_balance = proof_gen.sender_init_balance;
        let receiver_account = proof_gen.receiver_pub;
        let auditor_keys = proof_gen.auditor_keys.clone();
        let tx = proof_gen.finalize(&mut rng).expect("Ok");
        tx.verify(
            &sender_account,
            &sender_init_balance,
            &receiver_account,
            &auditor_keys,
            &mut rng,
        )
        .expect(&format!("Verify Sender proof of amount {amount:?}"));
    }
}

fn bench_transaction_sender(
    c: &mut Criterion,
    sender_account: ElgamalKeys,
    sender_balances: Vec<(Balance, CipherText)>,
    rcvr_pub_account: ElgamalPublicKey,
    auditor_keys: &BTreeSet<ElgamalPublicKey>,
) -> Vec<(Balance, CipherText, ConfidentialTransferProof)> {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, sender_balance) in &sender_balances {
        group.bench_with_input(
            BenchmarkId::new("Sender", *amount),
            &(amount, sender_balance),
            |b, (&amount, sender_balance)| {
                b.iter(|| {
                    ConfidentialTransferProof::new(
                        &sender_account,
                        sender_balance,
                        amount,
                        &rcvr_pub_account,
                        auditor_keys,
                        amount,
                        &mut rng,
                    )
                    .unwrap()
                })
            },
        );
    }
    group.finish();

    sender_balances
        .into_iter()
        .map(|(amount, sender_balance)| {
            eprintln!("Generate Sender Proof for: {amount}");
            let now = std::time::Instant::now();
            let tx = ConfidentialTransferProof::new(
                &sender_account,
                &sender_balance,
                amount,
                &rcvr_pub_account,
                auditor_keys,
                amount,
                &mut rng,
            )
            .unwrap();
            let size = tx.encoded_size();
            eprintln!(
                "elapsed: {:.0?} ms, size: {size:?}",
                now.elapsed().as_secs_f32() * 1_000.0
            );
            (amount, sender_balance, tx)
        })
        .collect()
}

fn bench_transaction_validator(
    c: &mut Criterion,
    sender_account: ElgamalPublicKey,
    receiver_account: ElgamalPublicKey,
    auditor_keys: &BTreeSet<ElgamalPublicKey>,
    transactions: &[(Balance, CipherText, ConfidentialTransferProof)],
) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, sender_balance, tx) in transactions {
        group.bench_with_input(
            BenchmarkId::new("Validator", amount),
            &(tx.clone(), sender_balance.clone()),
            |b, (tx, sender_balance)| {
                b.iter(|| {
                    tx.verify(
                        &sender_account,
                        &sender_balance,
                        &receiver_account,
                        auditor_keys,
                        &mut rng,
                    )
                    .unwrap()
                })
            },
        );
    }
    group.finish();
}

fn bench_transaction_receiver(
    c: &mut Criterion,
    receiver_account: ElgamalKeys,
    transactions: &[(Balance, CipherText, ConfidentialTransferProof)],
) {
    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, _, tx) in transactions {
        tx.receiver_verify(receiver_account.clone(), Some(*amount))
            .expect("Receiver verify");
        group.bench_with_input(
            BenchmarkId::new("Receiver", *amount),
            &(amount, tx.clone()),
            |b, (&amount, tx)| {
                b.iter(|| {
                    tx.receiver_verify(receiver_account.clone(), Some(amount))
                        .expect("Receiver verify")
                })
            },
        );
    }
    group.finish();
}

fn bench_transaction_auditor(
    c: &mut Criterion,
    id: u8,
    keys: &ElgamalKeys,
    transactions: &[(Balance, CipherText, ConfidentialTransferProof)],
) {
    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, _sender_balance, init_tx) in transactions {
        let label = format!("{:?} initial_balance ({:?})", id, amount);
        group.bench_with_input(
            BenchmarkId::new("Auditor", label),
            &init_tx,
            |b, init_tx| {
                b.iter(|| {
                    init_tx.auditor_verify(id, keys, None).unwrap();
                })
            },
        );
    }
    group.finish();
}
fn bench_transaction(c: &mut Criterion) {
    let mut rng = thread_rng();
    let auditors = testing::generate_auditors(MAX_AUDITORS as usize, &mut rng);
    let auditor_keys: BTreeSet<_> = auditors.iter().map(|keys| keys.public).collect();
    let (sender_account, sender_init_balance) = testing::create_account_with_amount(&mut rng, 0);
    let sender_pub_account = sender_account.public.clone();

    // Create a receiver account and load it with some assets.
    let (receiver_account, _receiver_balance) =
        testing::create_account_with_amount(&mut rng, RECEIVER_INIT_BALANCE);

    // Sender proof gen. bench each stage.
    let sender_balances: Vec<_> = [10 as Balance, 1_000_000_000]
        .iter()
        .map(|&amount| {
            (
                amount,
                testing::issue_assets(&mut rng, &sender_pub_account, &sender_init_balance, amount),
            )
        })
        .collect();
    for stage in 1..=7 {
        bench_transaction_sender_proof_stage(
            c,
            sender_account.clone(),
            &sender_balances,
            receiver_account.public.clone(),
            &auditor_keys,
            stage,
        );
    }

    let mut amounts: Vec<Balance> = Vec::new();
    // Make (Max - Min) sender accounts with initial balances of: [10^Min, 10^2, ..., 10^(Max-1)]
    for i in MIN_SENDER_BALANCE_ORDER..MAX_SENDER_BALANCE_ORDER {
        let amount = (10 as Balance).pow(i);
        amounts.push(amount);
    }
    let sender_balances: Vec<_> = amounts
        .into_iter()
        .map(|amount| {
            (
                amount,
                testing::issue_assets(&mut rng, &sender_pub_account, &sender_init_balance, amount),
            )
        })
        .collect();

    // Initialization
    let transactions = bench_transaction_sender(
        c,
        sender_account,
        sender_balances,
        receiver_account.public.clone(),
        &auditor_keys,
    );

    // Verify sender proofs.
    bench_transaction_validator(
        c,
        sender_pub_account.clone(),
        receiver_account.public.clone(),
        &auditor_keys,
        &transactions,
    );

    // Receiver verify transaction amount.
    bench_transaction_receiver(c, receiver_account.clone(), transactions.as_slice());

    // Mediator verify transaction amount.
    bench_transaction_auditor(c, 0, &auditors[0], transactions.as_slice());
}

criterion_group! {
    name = mercat_transaction;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
        // .measurement_time(Duration::new(60, 0));
    targets = bench_transaction,
}

criterion_main!(mercat_transaction);
