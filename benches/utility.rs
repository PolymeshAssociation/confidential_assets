use confidential_assets::{
    elgamal::ElgamalSecretKey, Account, Balance, EncryptedAmount, EncryptionKeys, EncryptionPubKey,
    MediatorAccount, PubAccount, Scalar, SecAccount,
};
use rand::{CryptoRng, RngCore};

#[cfg(not(feature = "balance_64"))]
#[allow(dead_code)]
pub mod balance_range {
    pub const MIN_ISSUED_AMOUNT_ORDER: u32 = 5;
    pub const MAX_ISSUED_AMOUNT_ORDER: u32 = 10;
    pub const MIN_SENDER_BALANCE_ORDER: u32 = 5;
    pub const MAX_SENDER_BALANCE_ORDER: u32 = 10;
}
#[cfg(feature = "balance_64")]
#[allow(dead_code)]
pub mod balance_range {
    pub const MIN_ISSUED_AMOUNT_ORDER: u32 = 10;
    pub const MAX_ISSUED_AMOUNT_ORDER: u32 = 20;
    pub const MIN_SENDER_BALANCE_ORDER: u32 = 10;
    pub const MAX_SENDER_BALANCE_ORDER: u32 = 20;
}

pub fn issue_assets<R: RngCore + CryptoRng>(
    rng: &mut R,
    pub_account: &PubAccount,
    init_balance: &EncryptedAmount,
    amount: Balance,
) -> EncryptedAmount {
    let (_, encrypted_amount) = pub_account
        .owner_enc_pub_key
        .encrypt_value(amount.into(), rng);
    init_balance + encrypted_amount
}

pub fn generate_mediator_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (EncryptionPubKey, MediatorAccount) {
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let mediator_enc_key = EncryptionKeys {
        public: mediator_elg_secret_key.get_public_key(),
        secret: mediator_elg_secret_key,
    };

    (
        mediator_enc_key.public,
        MediatorAccount {
            encryption_key: mediator_enc_key,
        },
    )
}

#[allow(dead_code)]
pub fn create_account_with_amount<R: RngCore + CryptoRng>(
    rng: &mut R,
    initial_amount: Balance,
) -> (Account, EncryptedAmount) {
    let secret_account = gen_keys(rng);

    let account = Account {
        public: PubAccount {
            owner_enc_pub_key: secret_account.enc_keys.public.clone(),
        },
        secret: secret_account,
    };
    let (_, initial_balance) = account
        .public
        .owner_enc_pub_key
        .encrypt_value(0u32.into(), rng);
    let initial_balance = if initial_amount > 0 {
        issue_assets(rng, &account.public, &initial_balance, initial_amount)
    } else {
        initial_balance
    };

    (account, initial_balance)
}

pub fn gen_keys<R: RngCore + CryptoRng>(rng: &mut R) -> SecAccount {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        public: elg_pub,
        secret: elg_secret,
    };

    SecAccount { enc_keys }
}
