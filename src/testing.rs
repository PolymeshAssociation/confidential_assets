use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::prelude::*;

use crate::{
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
        encryption_proofs::single_property_prover_with_transcript,
        range_proof::InRangeProof,
    },
    transaction::{
        Auditor, AuditorId, Auditors, ConfidentialTransferProof, CONFIDENTIAL_TRANSFER_PROOF_LABEL,
    },
    Balance, ElgamalKeys, ElgamalPublicKey, ElgamalSecretKey, Scalar, BALANCE_RANGE,
};

/// Used for testing/benchmarking.
#[derive(Clone)]
pub struct TestSenderProofGen {
    // Inputs.
    pub sender_sec: ElgamalSecretKey,
    pub sender_pub: ElgamalPublicKey,
    pub sender_init_balance: CipherText,
    pub sender_balance: Balance,
    pub receiver_pub: ElgamalPublicKey,
    pub auditor_keys: BTreeMap<AuditorId, ElgamalPublicKey>,
    pub keys: Vec<ElgamalPublicKey>,
    pub amount: Balance,
    // Temps.
    pub transcript: Transcript,
    pub last_stage: u32,
    pub witness: CommitmentWitness,
    pub gens: PedersenGens,
    pub balance_refresh_enc_blinding: Scalar,
    // Outputs.
    pub amounts: Option<CipherTextMultiKey>,
    pub amount_equal_cipher_proof: Option<CipherTextSameValueProof>,
    pub range_proofs: Option<InRangeProof>,
    pub refreshed_enc_balance: Option<CipherText>,
    pub balance_refreshed_same_proof: Option<CipherEqualSamePubKeyProof>,
    pub auditors: Auditors,
}

impl TestSenderProofGen {
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
            transcript: Transcript::new(CONFIDENTIAL_TRANSFER_PROOF_LABEL),
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

    pub fn run_to_stage<T: RngCore + CryptoRng>(
        &mut self,
        to_stage: u32,
        rng: &mut T,
    ) -> Result<()> {
        while self.last_stage < to_stage {
            self.run_next_stage(rng)?;
        }
        Ok(())
    }

    pub fn run_next_stage<T: RngCore + CryptoRng>(&mut self, rng: &mut T) -> Result<()> {
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
                let ciphertexts = self.amounts.as_ref().map(|a| a.ciphertexts()).unwrap();
                self.amount_equal_cipher_proof = Some(single_property_prover_with_transcript(
                    &mut self.transcript,
                    CipherTextSameValueProverAwaitingChallenge::new(
                        self.keys.clone(),
                        ciphertexts,
                        self.witness.clone(),
                        &self.gens,
                    ),
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
                self.balance_refreshed_same_proof = Some(single_property_prover_with_transcript(
                    &mut self.transcript,
                    CipherTextRefreshmentProverAwaitingChallenge::new(
                        self.sender_sec.clone(),
                        self.sender_pub.clone(),
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
                    &self.gens,
                    &mut self.transcript,
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
                            Auditor {
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

pub fn issue_assets<R: RngCore + CryptoRng>(
    rng: &mut R,
    pub_account: &ElgamalPublicKey,
    init_balance: &CipherText,
    amount: Balance,
) -> CipherText {
    let (_, encrypted_amount) = pub_account.encrypt_value(amount.into(), rng);
    init_balance + encrypted_amount
}

pub fn generate_auditors<R: RngCore + CryptoRng>(
    count: usize,
    rng: &mut R,
) -> BTreeMap<AuditorId, ElgamalKeys> {
    (0..count)
        .into_iter()
        .map(|n| {
            let secret_key = ElgamalSecretKey::new(Scalar::random(rng));
            let keys = ElgamalKeys {
                public: secret_key.get_public_key(),
                secret: secret_key,
            };

            (AuditorId(n as u32), keys)
        })
        .collect()
}

pub fn create_account_with_amount<R: RngCore + CryptoRng>(
    rng: &mut R,
    initial_amount: Balance,
) -> (ElgamalKeys, CipherText) {
    let account = gen_keys(rng);

    let (_, initial_balance) = account.public.encrypt_value(0u32.into(), rng);
    let initial_balance = if initial_amount > 0 {
        issue_assets(rng, &account.public, &initial_balance, initial_amount)
    } else {
        initial_balance
    };

    (account, initial_balance)
}

pub fn gen_keys<R: RngCore + CryptoRng>(rng: &mut R) -> ElgamalKeys {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    ElgamalKeys {
        public: elg_pub,
        secret: elg_secret,
    }
}
