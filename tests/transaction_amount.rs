use confidential_assets::{
    testing::{self, TestSenderProofGen},
    transaction::MAX_AUDITORS,
};
use rand::thread_rng;
use std::collections::BTreeSet;

#[test]
pub fn zero_transaction_amount() {
    let mut rng = thread_rng();
    let auditors = testing::generate_auditors(MAX_AUDITORS as usize, &mut rng);
    let auditor_keys: BTreeSet<_> = auditors.iter().map(|keys| keys.public).collect();
    let sender_balance = 1_000;
    let (sender_account, sender_init_balance) =
        testing::create_account_with_amount(&mut rng, sender_balance);
    let sender_pub_account = sender_account.public.clone();

    // Create a receiver account.
    let (receiver_account, _receiver_balance) = testing::create_account_with_amount(&mut rng, 0);
    let receiver_pub_account = receiver_account.public.clone();

    let amount = 0;
    let proof_gen = TestSenderProofGen::new(
        &sender_account,
        &sender_init_balance,
        sender_balance,
        &receiver_account.public,
        &auditor_keys,
        amount,
        &mut rng,
    );
    let tx = proof_gen.finalize(&mut rng).expect("Ok");

    let res = tx.verify(
        &sender_pub_account,
        &sender_init_balance,
        &receiver_pub_account,
        &auditor_keys,
        &mut rng,
    );
    eprintln!("verify sender proof: {res:?}");
    assert_eq!(res, Ok(()));
}
