use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use codec::Encode;
use confidential_assets::{
    elgamal::multi_key::{CipherTextMultiKey, CipherTextMultiKeyBuilder},
    elgamal::{CipherText, CipherTextHint, CommitmentWitness},
    errors::Result,
    proofs::{
        bulletproofs::PedersenGens,
        ciphertext_refreshment_proof::{
            CipherEqualSamePubKeyProof, CipherTextRefreshmentProverAwaitingChallenge,
        },
        ciphertext_same_value_proof::{
            CipherTextSameValueProof, CipherTextSameValueProverAwaitingChallenge,
        },
        encryption_proofs::single_property_prover,
        range_proof::InRangeProof,
    },
    transaction::{AuditorId, AuditorPayload, ConfidentialTransferProof, MAX_AUDITORS},
    Balance, ElgamalKeys, ElgamalPublicKey, ElgamalSecretKey, Scalar, BALANCE_RANGE,
};
use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;

mod utility;

// The sender's initial balance. Will be in:
// [10^MIN_SENDER_BALANCE_ORDER, 10^(MIN_SENDER_BALANCE_ORDER+1), ..., 10^MAX_SENDER_BALANCE_ORDER]
// The transferred amout on each iteration will be all the balance the sender has: 10^SENDER_BALANCE_ORDER
use utility::balance_range::{MAX_SENDER_BALANCE_ORDER, MIN_SENDER_BALANCE_ORDER};

// The receiver's initial balance.
const RECEIVER_INIT_BALANCE: Balance = 10000;

#[derive(Clone)]
struct SenderProofGen {
    // Inputs.
    sender_sec: ElgamalSecretKey,
    sender_pub: ElgamalPublicKey,
    sender_init_balance: CipherText,
    sender_balance: Balance,
    receiver_pub: ElgamalPublicKey,
    auditor_keys: BTreeMap<AuditorId, ElgamalPublicKey>,
    keys: Vec<ElgamalPublicKey>,
    pub amount: Balance,
    // Temps.
    last_stage: u32,
    witness: CommitmentWitness,
    gens: PedersenGens,
    balance_refresh_enc_blinding: Scalar,
    // Outputs.
    amounts: Option<CipherTextMultiKey>,
    amount_equal_cipher_proof: Option<CipherTextSameValueProof>,
    range_proofs: Option<InRangeProof>,
    refreshed_enc_balance: Option<CipherText>,
    balance_refreshed_same_proof: Option<CipherEqualSamePubKeyProof>,
    auditors: BTreeMap<AuditorId, AuditorPayload>,
}

impl SenderProofGen {
    pub fn new<T: RngCore + CryptoRng>(
        sender_account: &ElgamalKeys,
        sender_init_balance: &CipherText,
        sender_balance: Balance,
        receiver_pub_account: &ElgamalPublicKey,
        auditor_keys: &BTreeMap<AuditorId, ElgamalPublicKey>,
        amount: Balance,
        rng: &mut T,
    ) -> Self {
        let keys = ConfidentialTransferProof::keys(
            &sender_account.public,
            receiver_pub_account,
            auditor_keys,
        )
        .expect("keys");
        Self {
            // Inputs.
            sender_sec: sender_account.secret.clone(),
            sender_pub: sender_account.public.clone(),
            sender_init_balance: sender_init_balance.clone(),
            sender_balance,
            receiver_pub: receiver_pub_account.clone(),
            auditor_keys: auditor_keys.clone(),
            keys,
            amount,

            // Temps.
            last_stage: 0,
            witness: CommitmentWitness::new(amount.into(), Scalar::random(rng)),
            gens: PedersenGens::default(),
            balance_refresh_enc_blinding: Scalar::random(rng),

            // Outputs.
            amounts: None,
            amount_equal_cipher_proof: None,
            range_proofs: None,
            refreshed_enc_balance: None,
            balance_refreshed_same_proof: None,
            auditors: Default::default(),
        }
    }

    pub fn finalize<T: RngCore + CryptoRng>(
        mut self,
        rng: &mut T,
    ) -> Result<ConfidentialTransferProof> {
        self.run_to_stage(u32::MAX, rng)?;

        Ok(ConfidentialTransferProof {
            amounts: self.amounts.unwrap(),
            amount_equal_cipher_proof: self.amount_equal_cipher_proof.unwrap(),
            range_proofs: self.range_proofs.unwrap(),
            balance_refreshed_same_proof: self.balance_refreshed_same_proof.unwrap(),
            refreshed_enc_balance: self.refreshed_enc_balance.unwrap(),
            auditors: self.auditors,
        })
    }

    fn run_to_stage<T: RngCore + CryptoRng>(&mut self, to_stage: u32, rng: &mut T) -> Result<()> {
        while self.last_stage < to_stage {
            self.run_next_stage(rng)?;
        }
        Ok(())
    }

    fn run_next_stage<T: RngCore + CryptoRng>(&mut self, rng: &mut T) -> Result<()> {
        match self.last_stage {
            0 => {
                // Ensure the sender has enough funds.
                // Verify the sender's balance.
                self.sender_sec
                    .verify(&self.sender_init_balance, &self.sender_balance.into())?;
            }
            1 => {
                // Prove that the amount encrypted under different public keys are the same.
                self.amounts =
                    Some(CipherTextMultiKeyBuilder::new(&self.witness, self.keys.iter()).build());
            }
            2 => {
                self.amount_equal_cipher_proof = Some(single_property_prover(
                    CipherTextSameValueProverAwaitingChallenge {
                        keys: self.keys.clone(),
                        w: self.witness.clone(),
                        pc_gens: &self.gens,
                    },
                    rng,
                )?);
            }
            3 => {
                // Refresh the encrypted balance and prove that the refreshment was done
                // correctly.
                self.refreshed_enc_balance = Some(self.sender_init_balance.refresh_with_hint(
                    &self.sender_sec,
                    self.balance_refresh_enc_blinding,
                    &self.sender_balance.into(),
                )?);
            }
            4 => {
                let refreshed_enc_balance = self.refreshed_enc_balance.unwrap();
                self.balance_refreshed_same_proof = Some(single_property_prover(
                    CipherTextRefreshmentProverAwaitingChallenge::new(
                        self.sender_sec.clone(),
                        self.sender_init_balance,
                        refreshed_enc_balance,
                        &self.gens,
                    ),
                    rng,
                )?);
            }
            5 => {
                // Prove that the amount is not negative and
                // prove that the sender has enough funds.
                let amount_enc_blinding = self.witness.blinding();
                let updated_balance_blinding =
                    self.balance_refresh_enc_blinding - amount_enc_blinding;
                self.range_proofs = Some(InRangeProof::prove_multiple(
                    &[
                        self.amount.into(),
                        (self.sender_balance - self.amount).into(),
                    ],
                    &[amount_enc_blinding, updated_balance_blinding],
                    BALANCE_RANGE,
                    rng,
                )?);
            }
            6 => {
                // Add the necessary payload for auditors.
                self.auditors = self
                    .auditor_keys
                    .iter()
                    .enumerate()
                    .map(|(idx, (auditor_id, _auditor_enc_pub_key))| {
                        (
                            *auditor_id,
                            AuditorPayload {
                                amount_idx: (idx + 2) as u8,
                                encrypted_hint: CipherTextHint::new(&self.witness, rng),
                            },
                        )
                    })
                    .collect();
            }
            _ => {
                self.last_stage = u32::MAX;
                return Ok(());
            }
        }
        self.last_stage += 1;

        Ok(())
    }
}

fn bench_transaction_sender_proof_stage(
    c: &mut Criterion,
    sender_account: ElgamalKeys,
    sender_balances: &[(Balance, CipherText)],
    rcvr_pub_account: ElgamalPublicKey,
    auditor_keys: &BTreeMap<AuditorId, ElgamalPublicKey>,
    bench_stage: u32,
) {
    let mut rng = thread_rng();

    let proof_gens: Vec<_> = sender_balances
        .into_iter()
        .map(|(amount, sender_balance)| {
            let mut proof_gen = SenderProofGen::new(
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
            |b, proof_gen: &SenderProofGen| {
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
    auditor_keys: &BTreeMap<AuditorId, ElgamalPublicKey>,
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
    auditor_keys: &BTreeMap<AuditorId, ElgamalPublicKey>,
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
        tx.receiver_verify(receiver_account.clone(), *amount)
            .expect("Receiver verify");
        group.bench_with_input(
            BenchmarkId::new("Receiver", *amount),
            &(amount, tx.clone()),
            |b, (&amount, tx)| {
                b.iter(|| {
                    tx.receiver_verify(receiver_account.clone(), amount)
                        .unwrap()
                })
            },
        );
    }
    group.finish();
}

fn bench_transaction_auditor(
    c: &mut Criterion,
    id: AuditorId,
    keys: &ElgamalKeys,
    transactions: &[(Balance, CipherText, ConfidentialTransferProof)],
) {
    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, _sender_balance, init_tx) in transactions {
        let label = format!("{:?} initial_balance ({:?})", id.0, amount);
        group.bench_with_input(
            BenchmarkId::new("Auditor", label),
            &init_tx,
            |b, init_tx| {
                b.iter(|| {
                    init_tx.auditor_verify(id, keys).unwrap();
                })
            },
        );
    }
    group.finish();
}
fn bench_transaction(c: &mut Criterion) {
    let mut rng = thread_rng();
    let auditors = utility::generate_auditors(MAX_AUDITORS, &mut rng);
    let auditor_keys: BTreeMap<_, _> = auditors
        .iter()
        .map(|(id, keys)| (*id, keys.public))
        .collect();
    let (sender_account, sender_init_balance) = utility::create_account_with_amount(&mut rng, 0);
    let sender_pub_account = sender_account.public.clone();

    // Create a receiver account and load it with some assets.
    let (receiver_account, _receiver_balance) =
        utility::create_account_with_amount(&mut rng, RECEIVER_INIT_BALANCE);

    // Sender proof gen. bench each stage.
    let sender_balances: Vec<_> = [10 as Balance, 1_000_000_000]
        .iter()
        .map(|&amount| {
            (
                amount,
                utility::issue_assets(&mut rng, &sender_pub_account, &sender_init_balance, amount),
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
                utility::issue_assets(&mut rng, &sender_pub_account, &sender_init_balance, amount),
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

    // Mediator (AuditorId(0)) verify transaction amount.
    let mediator_id = AuditorId(0);
    let mediator = auditors.get(&mediator_id).unwrap();
    bench_transaction_auditor(c, mediator_id, mediator, transactions.as_slice());
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
