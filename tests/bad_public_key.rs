use codec::Decode;

use bulletproofs::PedersenGens;
use merlin::Transcript;

use confidential_assets::{
    elgamal::CommitmentWitness,
    errors::Error,
    proofs::{ciphertext_refreshment_proof::*, encryption_proofs::*, transcript::UpdateTranscript},
    testing::{self, TestSenderProofGen},
    transaction::MAX_AUDITORS,
    ElgamalKeys, ElgamalPublicKey, Scalar,
};
use rand::thread_rng;
use std::collections::BTreeSet;

#[test]
pub fn bad_public_key() {
    let mut rng = thread_rng();
    let auditors = testing::generate_auditors(MAX_AUDITORS as usize, &mut rng);
    let auditor_keys: BTreeSet<_> = auditors.iter().map(|keys| keys.public).collect();
    // Create sender account with a balance.
    let (sender_account, sender_init_balance) =
        testing::create_account_with_amount(&mut rng, 1_000);
    let sender_pub_account = sender_account.public.clone();

    let gens = PedersenGens::default();

    let refresh_blinding = Scalar::ONE;
    let y_diff = *sender_init_balance.y - (refresh_blinding * gens.B_blinding);

    let mut transcript = Transcript::new(ENCRYPTION_PROOFS_LABEL);

    let z = Scalar::ZERO; //Scalar::random(&mut rng);
    let a = y_diff;
    let b = gens.B_blinding;
    let initial_message = CipherTextRefreshmentInitialMessage {
        a: a.into(),
        b: b.into(),
    };
    let c = initial_message
        .update_transcript(&mut transcript)
        .unwrap()
        .x()
        .clone();

    let final_response = CipherTextRefreshmentFinalResponse(z.into());

    // Bad sender account.
    let bad_pk = c.invert() * ((z * gens.B_blinding) - b);
    let buf = [0u8; 96];
    let mut sender_account: ElgamalKeys = Decode::decode(&mut &buf[..]).unwrap();
    sender_account.public = ElgamalPublicKey {
        pub_key: bad_pk.into(),
    };
    let sender_fake_pub_account = sender_account.public.clone();

    // Create a receiver account.
    let (receiver_account, _receiver_balance) = testing::create_account_with_amount(&mut rng, 0);
    let receiver_pub_account = receiver_account.public.clone();

    let amount = 1_000u64;
    let mut proof_gen = TestSenderProofGen::new(
        &sender_account,
        &sender_init_balance,
        amount,
        &receiver_account.public,
        &auditor_keys,
        amount,
        &mut rng,
    );
    proof_gen.balance_refresh_enc_blinding = refresh_blinding;
    // Skip sender balance check.
    proof_gen.last_stage = 1;

    proof_gen.run_to_stage(1, &mut rng).expect("Ok");
    proof_gen.run_to_stage(2, &mut rng).expect("Ok");
    proof_gen.run_to_stage(3, &mut rng).expect("Ok");

    // Fake refreshed balance and refreshment proof.
    // Refresh the encrypted balance and prove that the refreshment was done
    // correctly.
    let witness = CommitmentWitness::new(amount.into(), proof_gen.balance_refresh_enc_blinding);
    proof_gen.refreshed_enc_balance = Some(sender_fake_pub_account.encrypt(&witness));
    proof_gen.last_stage = 4;

    proof_gen.balance_refreshed_same_proof =
        Some((initial_message.clone(), final_response.clone()));
    proof_gen.last_stage = 5;

    proof_gen.run_to_stage(6, &mut rng).expect("Ok");

    let tx = proof_gen.finalize(&mut rng).expect("Ok");

    let z = *final_response.0;
    let a = initial_message.a.decompress();
    let b = initial_message.b.decompress();
    let inner = tx.inner_proof().expect("Ok");
    let x = *sender_init_balance.x - *inner.refreshed_enc_balance.x;
    let y = *sender_init_balance.y - *inner.refreshed_enc_balance.y;
    // This check fails like it should.
    assert!(z * y != a + c * x);
    // ATTACK: causes this to pass.
    assert!(z * gens.B_blinding == b + (c * *sender_fake_pub_account.pub_key));
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
        Err(Error::CiphertextSameValueFinalResponseVerificationError { check: 0 })
    );
}
