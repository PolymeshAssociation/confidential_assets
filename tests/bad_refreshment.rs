use codec::Decode;

use confidential_assets::{
    elgamal::CommitmentWitness,
    errors::Error,
    proofs::{
        ciphertext_refreshment_proof::CipherTextRefreshmentProverAwaitingChallenge,
        encryption_proofs::single_property_prover,
    },
    testing::{self, TestSenderProofGen},
    transaction::MAX_AUDITORS,
    Scalar,
};
use rand::thread_rng;
use std::collections::BTreeSet;

#[test]
pub fn bad_refreshment1() {
    let mut rng = thread_rng();
    let auditors = testing::generate_auditors(MAX_AUDITORS as usize, &mut rng);
    let auditor_keys: BTreeSet<_> = auditors.iter().map(|keys| keys.public).collect();
    let (sender_account, sender_init_balance) = testing::create_account_with_amount(&mut rng, 0);
    let sender_pub_account = sender_account.public.clone();

    // Create a receiver account.
    let (receiver_account, _receiver_balance) = testing::create_account_with_amount(&mut rng, 0);
    let receiver_pub_account = receiver_account.public.clone();

    let amount = 1_000;
    let mut proof_gen = TestSenderProofGen::new(
        &sender_account,
        &sender_init_balance,
        amount,
        &receiver_account.public,
        &auditor_keys,
        amount,
        &mut rng,
    );
    // Skip sender balance check.
    proof_gen.last_stage = 1;

    proof_gen.run_to_stage(1, &mut rng).expect("Ok");
    proof_gen.run_to_stage(2, &mut rng).expect("Ok");
    proof_gen.run_to_stage(3, &mut rng).expect("Ok");

    // Fake refreshed balance and refreshment proof.
    // Refresh the encrypted balance and prove that the refreshment was done
    // correctly.
    let fake_balance = 1_000_000_000u64;
    let fake_witness =
        CommitmentWitness::new(fake_balance.into(), proof_gen.balance_refresh_enc_blinding);
    let fake_enc_balance = sender_pub_account.encrypt(&fake_witness);
    proof_gen.refreshed_enc_balance = Some(fake_enc_balance);
    proof_gen.last_stage = 4;

    let refreshed_enc_balance = proof_gen.refreshed_enc_balance.unwrap();
    proof_gen.balance_refreshed_same_proof = Some(
        single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                proof_gen.sender_sec.clone(),
                proof_gen.sender_pub.clone(),
                proof_gen.sender_init_balance,
                refreshed_enc_balance,
                &proof_gen.gens,
            ),
            &mut rng,
        )
        .unwrap(),
    );
    // Set `a`, `b` and `z` to zero:
    let buf = [0u8; 96];
    proof_gen.balance_refreshed_same_proof = Some(Decode::decode(&mut &buf[..]).unwrap());
    eprintln!(
        "-- refreshment proof: {:?}",
        proof_gen.balance_refreshed_same_proof
    );
    proof_gen.last_stage = 5;

    proof_gen.run_to_stage(5, &mut rng).expect("Ok");
    proof_gen.run_to_stage(6, &mut rng).expect("Ok");

    let tx = proof_gen.finalize(&mut rng).expect("Ok");

    let res = tx.verify(
        &sender_pub_account,
        &sender_init_balance,
        &receiver_pub_account,
        &auditor_keys,
        &mut rng,
    );
    eprintln!("verify sender proof: {res:?}");
    assert_eq!(res, Err(Error::VerificationError));
}

#[test]
pub fn bad_refreshment2() {
    let mut rng = thread_rng();
    let auditors = testing::generate_auditors(MAX_AUDITORS as usize, &mut rng);
    let auditor_keys: BTreeSet<_> = auditors.iter().map(|keys| keys.public).collect();
    let (sender_account, sender_init_balance) = testing::create_account_with_amount(&mut rng, 0);
    let sender_pub_account = sender_account.public.clone();

    // Create a receiver account.
    let (receiver_account, _receiver_balance) = testing::create_account_with_amount(&mut rng, 0);
    let receiver_pub_account = receiver_account.public.clone();

    let amount = 1_000;
    let mut proof_gen = TestSenderProofGen::new(
        &sender_account,
        &sender_init_balance,
        amount,
        &receiver_account.public,
        &auditor_keys,
        amount,
        &mut rng,
    );
    // Skip sender balance check.
    proof_gen.last_stage = 1;

    proof_gen.run_to_stage(1, &mut rng).expect("Ok");
    proof_gen.run_to_stage(2, &mut rng).expect("Ok");
    proof_gen.run_to_stage(3, &mut rng).expect("Ok");

    // Fake refreshed balance and refreshment proof.
    // Refresh the encrypted balance and prove that the refreshment was done
    // correctly.
    let fake_balance = 1_000_000_000u64;
    let fake_witness =
        CommitmentWitness::new(fake_balance.into(), proof_gen.balance_refresh_enc_blinding);
    let fake_enc_balance = sender_pub_account.encrypt(&fake_witness);
    proof_gen.refreshed_enc_balance = Some(fake_enc_balance);
    proof_gen.last_stage = 4;

    let refreshed_enc_balance = proof_gen.refreshed_enc_balance.unwrap();
    proof_gen.balance_refreshed_same_proof = Some(
        single_property_prover(
            CipherTextRefreshmentProverAwaitingChallenge::new(
                proof_gen.sender_sec.clone(),
                proof_gen.sender_pub.clone(),
                proof_gen.sender_init_balance,
                refreshed_enc_balance,
                &proof_gen.gens,
            ),
            &mut rng,
        )
        .unwrap(),
    );
    // Set `z` to zero:
    if let Some(proof) = &mut proof_gen.balance_refreshed_same_proof {
        proof.1 .0 = Scalar::zero().into();
    }
    eprintln!(
        "-- refreshment proof: {:?}",
        proof_gen.balance_refreshed_same_proof
    );
    proof_gen.last_stage = 5;

    proof_gen.run_to_stage(5, &mut rng).expect("Ok");
    proof_gen.run_to_stage(6, &mut rng).expect("Ok");

    let tx = proof_gen.finalize(&mut rng).expect("Ok");

    let res = tx.verify(
        &sender_pub_account,
        &sender_init_balance,
        &receiver_pub_account,
        &auditor_keys,
        &mut rng,
    );
    eprintln!("verify sender proof: {res:?}");
    assert_eq!(
        res,
        Err(Error::CiphertextRefreshmentFinalResponseVerificationError { check: 1 })
    );
}
