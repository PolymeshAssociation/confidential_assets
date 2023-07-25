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
use sp_std::{fmt, vec::Vec};

pub use curve25519_dalek::scalar::Scalar;

#[macro_use]
pub(crate) mod macros;

pub mod errors;

pub mod codec_wrapper;
pub mod elgamal;
pub mod proofs;

pub use elgamal::{
    CipherText, CipherTextWithHint, CompressedElgamalPublicKey, ElgamalPublicKey, ElgamalSecretKey,
};
pub use errors::{ErrorKind, Fallible};
pub use proofs::{
    ciphertext_refreshment_proof::CipherEqualSamePubKeyProof, correctness_proof::CorrectnessProof,
    encrypting_same_value_proof::CipherEqualDifferentPubKeyProof, range_proof::InRangeProof,
    wellformedness_proof::WellformednessProof,
};

/// The balance value to keep confidential.
///
/// Since Elgamal decryption involves searching the entire
/// space of possible values. We have limited
/// the size of the balance to 32 bits (or 64 bits with feature flag `balance_64`).
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
#[cfg(not(feature = "balance_64"))]
pub type Balance = u32;
#[cfg(not(feature = "balance_64"))]
pub const BALANCE_RANGE: u32 = 32;
#[cfg(feature = "balance_64")]
pub type Balance = u64;
#[cfg(feature = "balance_64")]
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

/// Holds contents of the public portion of an account which can be safely put on the chain.
#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PubAccountTx {
    pub pub_account: PubAccount,
    pub initial_balance: EncryptedAmount,
    pub initial_balance_correctness_proof: CorrectnessProof,
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

/// The interface for the account creation.
pub trait AccountCreatorInitializer {
    /// Creates a public account for a user and initializes the balance to zero.
    /// Corresponds to `CreateAccount` method of the MERCAT paper.
    /// This function assumes that the given input `account_id` is unique.
    fn create<T: RngCore + CryptoRng>(
        &self,
        secret: &SecAccount,
        rng: &mut T,
    ) -> Fallible<PubAccountTx>;
}

/// The interface for the verifying the account creation.
pub trait AccountCreatorVerifier {
    /// Called by the validators to ensure that the account was created correctly.
    fn verify(&self, account: &PubAccountTx) -> Fallible<()>;
}

// -------------------------------------------------------------------------------------
// -                               Transaction State                                   -
// -------------------------------------------------------------------------------------

/// Represents the three substates (started, verified, rejected) of a
/// confidential transaction state.
#[derive(Copy, Clone, PartialEq, Eq, Encode, Decode, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TxSubstate {
    /// The action on transaction has been taken but is not verified yet.
    Started,
    /// The action on transaction has been verified by validators.
    Validated,
    /// The action on transaction has failed the verification by validators.
    Rejected,
}

impl fmt::Display for TxSubstate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            TxSubstate::Started => "started",
            TxSubstate::Validated => "validated",
            TxSubstate::Rejected => "rejected",
        };
        write!(f, "{}", str)
    }
}

/// Represents the two states (initialized, justified) of a
/// confidential asset issuance transaction.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AssetTxState {
    Initialization(TxSubstate),
    Justification(TxSubstate),
}

impl fmt::Display for AssetTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetTxState::Initialization(substate) => {
                write!(f, "asset-initialization-{}", substate)
            }
            AssetTxState::Justification(substate) => write!(f, "asset-justification-{}", substate),
        }
    }
}

impl core::fmt::Debug for AssetTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetTxState::Initialization(substate) => {
                write!(f, "asset-initialization-{}", substate)
            }
            AssetTxState::Justification(substate) => write!(f, "asset-justification-{}", substate),
        }
    }
}

/// Represents the four states (initialized, justified, finalized, reversed) of a
/// confidential transaction.
#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransferTxState {
    Initialization(TxSubstate),
    Finalization(TxSubstate),
    Justification(TxSubstate),
    Reversal(TxSubstate),
}

impl fmt::Display for TransferTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferTxState::Initialization(substate) => {
                write!(f, "transfer-initialization-{}", substate)
            }
            TransferTxState::Finalization(substate) => {
                write!(f, "transfer-finalization-{}", substate)
            }
            TransferTxState::Justification(substate) => {
                write!(f, "transfer-justification-{}", substate)
            }
            TransferTxState::Reversal(substate) => write!(f, "transfer-reversal-{}", substate),
        }
    }
}

impl core::fmt::Debug for TransferTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferTxState::Initialization(substate) => write!(f, "initialization_{}", substate),
            TransferTxState::Finalization(substate) => write!(f, "finalization_{}", substate),
            TransferTxState::Justification(substate) => write!(f, "justification_{}", substate),
            TransferTxState::Reversal(substate) => write!(f, "reversal_{}", substate),
        }
    }
}

// -------------------------------------------------------------------------------------
// -                                 Asset Issuance                                    -
// -------------------------------------------------------------------------------------

/// Asset memo holds the contents of an asset issuance transaction.
#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AssetMemo {
    pub enc_issued_amount: EncryptedAmount,
}

/// Holds the public portion of an asset issuance transaction after initialization.
/// This can be placed on the chain.
#[derive(Clone, Encode, Decode, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InitializedAssetTx {
    pub account: PubAccount,
    pub memo: AssetMemo,
    pub balance_wellformedness_proof: WellformednessProof,
    pub balance_correctness_proof: CorrectnessProof,
    pub auditors_payload: Vec<AuditorPayload>,
}

/// The interface for the confidential asset issuance transaction.
pub trait AssetTransactionIssuer {
    /// Initializes a confidential asset issue transaction. Note that the returning
    /// values of this function contain sensitive information. Corresponds
    /// to `CreateAssetIssuanceTx` MERCAT whitepaper.
    fn initialize_asset_transaction<T: RngCore + CryptoRng>(
        &self,
        issr_account: &Account,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
        amount: Balance,
        rng: &mut T,
    ) -> Fallible<InitializedAssetTx>;
}

pub trait AssetTransactionVerifier {
    /// Called by validators to verify the justification and processing of the transaction.
    fn verify_asset_transaction(
        &self,
        amount: Balance,
        justified_asset_tx: &InitializedAssetTx,
        issr_account: &PubAccount,
        auditors_enc_pub_keys: &[(AuditorId, EncryptionPubKey)],
    ) -> Fallible<()>;
}

pub trait AssetTransactionAuditor {
    /// Verify the initialized, and justified transactions.
    /// Audit the sender's encrypted amount.
    fn audit_asset_transaction(
        &self,
        justified_asset_tx: &InitializedAssetTx,
        issuer_account: &PubAccount,
        auditor_enc_keys: &(AuditorId, EncryptionKeys),
    ) -> Fallible<()>;
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
    pub fn get_amount(&self, enc_amount: Option<&EncryptedAmountWithHint>) -> Fallible<Balance> {
        match (self, enc_amount) {
            (Self::Amount(amount), _) => Ok(*amount),
            (Self::Encrypted(keys), Some(enc_amount)) => {
                Ok(keys.secret.const_time_decrypt(enc_amount)?)
            }
            _ => Err(ErrorKind::CipherTextDecryptionError.into()),
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
    ) -> Fallible<InitializedTransferTx>;
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
    ) -> Fallible<FinalizedTransferTx>;
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
    ) -> Fallible<JustifiedTransferTx>;
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
    ) -> Fallible<()>;
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
    ) -> Fallible<()>;
}

pub mod account;
pub mod asset;
pub mod transaction;
