use confidential_assets::{
    elgamal::ElgamalSecretKey, Balance, ElgamalKeys, ElgamalPublicKey, EncryptedAmount, Scalar,
};
use rand::{CryptoRng, RngCore};

pub mod balance_range {
    pub const MIN_SENDER_BALANCE_ORDER: u32 = 10;
    pub const MAX_SENDER_BALANCE_ORDER: u32 = 20;
}

pub fn issue_assets<R: RngCore + CryptoRng>(
    rng: &mut R,
    pub_account: &ElgamalPublicKey,
    init_balance: &EncryptedAmount,
    amount: Balance,
) -> EncryptedAmount {
    let (_, encrypted_amount) = pub_account.encrypt_value(amount.into(), rng);
    init_balance + encrypted_amount
}

pub fn generate_mediator_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (ElgamalPublicKey, ElgamalKeys) {
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let mediator_enc_key = ElgamalKeys {
        public: mediator_elg_secret_key.get_public_key(),
        secret: mediator_elg_secret_key,
    };

    (mediator_enc_key.public, mediator_enc_key)
}

#[allow(dead_code)]
pub fn create_account_with_amount<R: RngCore + CryptoRng>(
    rng: &mut R,
    initial_amount: Balance,
) -> (ElgamalKeys, EncryptedAmount) {
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
