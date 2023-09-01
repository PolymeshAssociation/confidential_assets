use merlin::Transcript;

use curve25519_dalek::ristretto::RistrettoPoint;

use confidential_assets::{
    proofs::{
        bulletproofs::PedersenGens,
        encryption_proofs::{ENCRYPTION_PROOFS_CHALLENGE_LABEL, ENCRYPTION_PROOFS_LABEL},
        transcript::{TranscriptProtocol, UpdateTranscript},
    },
    Balance, ElgamalPublicKey,
    transaction::ConfidentialTransferProof,
};

fn setup_correctness_search(init_tx: &ConfidentialTransferProof) -> (RistrettoPoint, RistrettoPoint) {
    let gens = &PedersenGens::default();

    // Setup "proof" verification.
    let (init_msg, fin_msg) = init_tx.amount_correctness_proof;
    let cipher = init_tx.memo.enc_amount_using_sender;

    // Calculate 'challenge' value.
    let mut transcript = Transcript::new(ENCRYPTION_PROOFS_LABEL);
    init_msg.update_transcript(&mut transcript).unwrap();
    let challenge = transcript
        .scalar_challenge(ENCRYPTION_PROOFS_CHALLENGE_LABEL)
        .unwrap()
        .x()
        .clone();

    let fin_msg_b_blinding = fin_msg.0 * gens.B_blinding;
    let challenge_cipher = challenge * cipher.y;
    let target = (init_msg.b + challenge_cipher) - fin_msg_b_blinding;

    (gens.B, target * challenge.invert())
}

pub fn brute_force_amount_correctness(
    init_tx: &ConfidentialTransferProof,
    _sender: &ElgamalPublicKey,
) -> Option<Balance> {
    // Setup "proof" verification.
    let (gen_b, target) = setup_correctness_search(init_tx);

    let discrete_log = confidential_assets::elgamal::discrete_log::DiscreteLog::new(gen_b);

    discrete_log.decode(target)
}
