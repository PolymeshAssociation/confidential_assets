mod utility;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use confidential_assets::{
    account::{AccountCreator, AccountValidator},
    AccountCreatorInitializer, AccountCreatorVerifier,
};
use rand::thread_rng;

const IDS: [u32; 5] = [10, 20, 300, 4000, 65535];

fn bench_account_creation(c: &mut Criterion) {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("MERCAT Account");

    for id in IDS {
        let label = format!("asset_id: {:?}", id);
        let secret_account = utility::gen_keys(&mut rng);
        group.bench_with_input(
            BenchmarkId::new("Creator", label),
            &secret_account,
            |b, secret_account| {
                b.iter(|| {
                    let account_creator = AccountCreator;
                    account_creator.create(&secret_account, &mut rng).unwrap();
                })
            },
        );
    }

    for id in IDS {
        let label = format!("asset_id: {:?}", id);
        let account = utility::create_account(&mut rng);
        group.bench_with_input(
            BenchmarkId::new("Validator", label),
            &account,
            |b, account| {
                b.iter(|| {
                    let validator = AccountValidator;
                    validator.verify(account).unwrap()
                })
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = mercat_account;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
        // .measurement_time(Duration::new(60, 0));
    targets = bench_account_creation,
}

criterion_main!(mercat_account);
