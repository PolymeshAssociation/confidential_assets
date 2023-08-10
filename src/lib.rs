//! mercat is the library that implements the confidential transactions
//! of the MERCAT, as defined in the section 6 of the whitepaper.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use rand_core::{CryptoRng, RngCore};

use zeroize::{Zeroize, ZeroizeOnDrop};

use codec::{Decode, Encode};
use sp_std::vec::Vec;

pub use curve25519_dalek::scalar::Scalar;

#[macro_use]
pub(crate) mod macros;

pub mod errors;

pub mod codec_wrapper;
pub mod elgamal;
pub mod proofs;
pub mod transaction;

pub use elgamal::{
    CipherText, CipherTextWithHint, CompressedElgamalPublicKey, ElgamalPublicKey, ElgamalSecretKey,
};
pub use errors::{Error, Result};
pub use proofs::{
    ciphertext_refreshment_proof::CipherEqualSamePubKeyProof, correctness_proof::CorrectnessProof,
    encrypting_same_value_proof::CipherEqualDifferentPubKeyProof, range_proof::InRangeProof,
    wellformedness_proof::WellformednessProof,
};

/// The balance value to keep confidential.
///
/// Since Elgamal decryption involves searching the entire
/// space of possible values. We have limited
/// the size of the balance to 64 bits.
///
/// Possible remedies are:
/// #0 limit the range even further since confidential values
///     in the context of Polymesh could be limited.
/// #1 use AVX2 instruction sets if available on the target
///    architectures. Our preliminary investigation using
///    `curve25519_dalek`'s AVX2 features doesn't show a
///    significant improvment.
/// #2 Given the fact that encrypted Elgamal values are mostly used
///    for zero-knowledge proof generations, it is very likely that
///    we won't need to decrypt the encrypted values very often.
///    We can recommend that applications use a different faster
///    encryption mechanism to store the confidentional values on disk.
pub type Balance = u64;
pub const BALANCE_RANGE: u32 = 64;

// -------------------------------------------------------------------------------------
// -                                 New Type Def                                      -
// -------------------------------------------------------------------------------------

/// Holds ElGamal encryption public key.
pub type EncryptionPubKey = ElgamalPublicKey;

/// Holds a compressed ElGamal encryption public key.
pub type CompressedEncryptionPubKey = CompressedElgamalPublicKey;

/// Holds ElGamal encryption secret key.
pub type EncryptionSecKey = ElgamalSecretKey;

/// Holds ElGamal encryption keys.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKeys {
    #[zeroize(skip)]
    pub public: EncryptionPubKey,
    pub secret: EncryptionSecKey,
}

/// New type for Twisted ElGamal ciphertext of account amounts/balances.
pub type EncryptedAmount = CipherText;

/// New type for ElGamal ciphertext of a transferred amount.
pub type EncryptedAmountWithHint = CipherTextWithHint;

// -------------------------------------------------------------------------------------
// -                                    Account                                        -
// -------------------------------------------------------------------------------------

#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MediatorAccount {
    pub encryption_key: EncryptionKeys,
}

#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PubAccount {
    pub owner_enc_pub_key: EncryptionPubKey,
}

impl From<EncryptionKeys> for PubAccount {
    fn from(enc_keys: EncryptionKeys) -> Self {
        Self {
            owner_enc_pub_key: enc_keys.public,
        }
    }
}

impl From<&EncryptionKeys> for PubAccount {
    fn from(enc_keys: &EncryptionKeys) -> Self {
        Self::from(enc_keys.clone())
    }
}

/// Holds the secret keys and asset id of an account. This cannot be put on the change.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecAccount {
    pub enc_keys: EncryptionKeys,
}

impl From<EncryptionKeys> for SecAccount {
    fn from(enc_keys: EncryptionKeys) -> Self {
        Self { enc_keys }
    }
}

impl From<&EncryptionKeys> for SecAccount {
    fn from(enc_keys: &EncryptionKeys) -> Self {
        Self::from(enc_keys.clone())
    }
}

/// Wrapper for both the secret and public account info
#[derive(Clone, Debug)]
pub struct Account {
    pub public: PubAccount,
    pub secret: SecAccount,
}

impl From<EncryptionKeys> for Account {
    fn from(enc_keys: EncryptionKeys) -> Self {
        Self {
            public: PubAccount {
                owner_enc_pub_key: enc_keys.public,
            },
            secret: SecAccount { enc_keys },
        }
    }
}

impl From<&EncryptionKeys> for Account {
    fn from(enc_keys: &EncryptionKeys) -> Self {
        Self::from(enc_keys.clone())
    }
}

// -------------------------------------------------------------------------------------
// -                       Confidential Transfer Transaction                           -
// -------------------------------------------------------------------------------------

pub type AuditorId = u32;

#[derive(Clone, Debug)]
pub enum AmountSource<'a> {
    Encrypted(&'a EncryptionKeys),
    Amount(Balance),
}

impl From<Balance> for AmountSource<'_> {
    fn from(val: Balance) -> Self {
        Self::Amount(val)
    }
}

impl AmountSource<'_> {
    pub fn get_amount(&self, enc_amount: Option<&EncryptedAmountWithHint>) -> Result<Balance> {
        match (self, enc_amount) {
            (Self::Amount(amount), _) => Ok(*amount),
            (Self::Encrypted(keys), Some(enc_amount)) => {
                Ok(keys.secret.const_time_decrypt(enc_amount)?)
            }
            _ => Err(Error::CipherTextDecryptionError.into()),
        }
    }
}

#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditorPayload {
    pub auditor_id: AuditorId,
    pub encrypted_amount: EncryptedAmountWithHint,
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
}

/// Holds the memo for confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransferTxMemo {
    pub enc_amount_using_sender: EncryptedAmount,
    pub enc_amount_using_receiver: EncryptedAmount,
    pub refreshed_enc_balance: EncryptedAmount,
    pub enc_amount_for_mediator: Option<EncryptedAmountWithHint>,
}

/// Holds the proofs and memo of the confidential transaction sent by the sender.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitializedTransferTx {
    pub amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof,
    pub non_neg_amount_proof: InRangeProof,
    pub enough_fund_proof: InRangeProof,
    pub memo: TransferTxMemo,
    pub balance_refreshed_same_proof: CipherEqualSamePubKeyProof,
    pub amount_correctness_proof: CorrectnessProof,
    pub auditors_payload: Vec<AuditorPayload>,
}

/// TODO: remove, not needed.
#[derive(Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FinalizedTransferTx {}

/// Wrapper for the contents and auditors' payload.
#[derive(Clone, Encode, Decode, Debug)]
pub struct JustifiedTransferTx {}

/// The interface for confidential transaction.
pub trait TransferTransactionSender {
    /// This is called by the sender of a confidential transaction. The outputs
    /// can be safely placed on the chain. It corresponds to `CreateCTX` function of
    /// MERCAT paper.
    fn create_transaction<T: RngCore + CryptoRng>(
        &self,
        sender_account: &Account,
        sender_init_balance: &EncryptedAmount,
        sender_balance: Balance,
        receiver_pub_account: &PubAccount,
        mediator_pub_key: Option<&EncryptionPubKey>,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Result<InitializedTransferTx>;
}

pub trait TransferTransactionReceiver {
    /// This function is called the receiver of the transaction to finalize and process
    /// the transaction. It corresponds to `FinalizeCTX` and `ProcessCTX` functions
    /// of the MERCAT paper.
    fn finalize_transaction(
        &self,
        initialized_transaction: &InitializedTransferTx,
        receiver_account: Account,
        amount: Balance,
    ) -> Result<FinalizedTransferTx>;
}

pub trait TransferTransactionMediator {
    /// Justify the transaction by mediator.
    fn justify_transaction<R: RngCore + CryptoRng>(
        &self,
        init_tx: &InitializedTransferTx,
        amount_source: AmountSource,
        sender_account: &PubAccount,
        sender_init_balance: &EncryptedAmount,
        receiver_account: &PubAccount,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        rng: &mut R,
    ) -> Result<JustifiedTransferTx>;
}

pub trait TransferTransactionVerifier {
    /// Verify the transaction's ZK proofs.
    /// The receiver and mediator need to verify the transaction amount.
    fn verify_transaction<R: RngCore + CryptoRng>(
        &self,
        init_tx: &InitializedTransferTx,
        sender_account: &PubAccount,
        sender_init_balance: &EncryptedAmount,
        receiver_account: &PubAccount,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        rng: &mut R,
    ) -> Result<()>;
}

pub trait TransferTransactionAuditor {
    /// Verify the initialized, finalized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_transaction(
        &self,
        init_tx: &InitializedTransferTx,
        sender_account: &PubAccount,
        receiver_account: &PubAccount,
        auditor_enc_keys: &(AuditorId, EncryptionKeys),
    ) -> Result<()>;
}
