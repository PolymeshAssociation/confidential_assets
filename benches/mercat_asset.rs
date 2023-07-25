mod utility;
use confidential_assets::{
    asset::{AssetIssuer, AssetValidator},
    Account, AssetTransactionIssuer, AssetTransactionVerifier, Balance, InitializedAssetTx,
    PubAccount,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;

// The issued amount. Will be in:
// [10^MIN_ISSUED_AMOUNT_ORDER, 10^(MIN_ISSUED_AMOUNT_ORDER+1), ..., 10^MAX_ISSUED_AMOUNT_ORDER]
use utility::balance_range::{MAX_ISSUED_AMOUNT_ORDER, MIN_ISSUED_AMOUNT_ORDER};

fn bench_transaction_issuer(
    c: &mut Criterion,
    issuer_account: Account,
    amounts: Vec<Balance>,
) -> Vec<InitializedAssetTx> {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("MERCAT Asset");
    for amount in &amounts {
        group.bench_with_input(BenchmarkId::new("Issuer", *amount), amount, |b, &amount| {
            b.iter(|| {
                let issuer = AssetIssuer;
                issuer
                    .initialize_asset_transaction(&issuer_account, &[], amount, &mut rng)
                    .unwrap()
            })
        });
    }
    group.finish();

    amounts
        .iter()
        .map(|&amount| {
            let issuer = AssetIssuer;
            issuer
                .initialize_asset_transaction(&issuer_account.clone(), &[], amount, &mut rng)
                .unwrap()
        })
        .collect()
}

fn bench_transaction_validator(
    c: &mut Criterion,
    transactions: Vec<InitializedAssetTx>,
    issuer_account: PubAccount,
) {
    let indexed_transaction: Vec<((String, Balance), InitializedAssetTx)> =
        (MIN_ISSUED_AMOUNT_ORDER..MAX_ISSUED_AMOUNT_ORDER)
            .map(|i| {
                let amount = (10 as Balance).pow(i);
                (format!("issued_amount ({:?})", amount), amount)
            })
            .zip(transactions)
            .collect();

    let mut group = c.benchmark_group("MERCAT Asset");
    for ((label, amount), tx) in &indexed_transaction {
        group.bench_with_input(
            BenchmarkId::new("Validator", label),
            &(amount, tx),
            |b, (&amount, tx)| {
                b.iter(|| {
                    let validator = AssetValidator;
                    validator
                        .verify_asset_transaction(amount, &tx, &issuer_account, &[])
                        .unwrap()
                })
            },
        );
    }
    group.finish();
}

fn bench_asset_transaction(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (issuer_account, _issuer_init_balance) = utility::create_account_with_amount(&mut rng, 0);

    let issued_amounts: Vec<Balance> = (MIN_ISSUED_AMOUNT_ORDER..MAX_ISSUED_AMOUNT_ORDER)
        .map(|i| (10 as Balance).pow(i))
        .collect();

    // Initialization
    let transactions = bench_transaction_issuer(c, issuer_account.clone(), issued_amounts);

    // Validation
    bench_transaction_validator(c, transactions, issuer_account.public);
}

criterion_group! {
    name = mercat_asset;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
        // .measurement_time(Duration::new(60, 0));
    targets = bench_asset_transaction,
}

criterion_main!(mercat_asset);
