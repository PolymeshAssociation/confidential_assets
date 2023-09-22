#[cfg(feature = "std")]
use thiserror::Error;

use crate::Balance;

/// Confidential asset error
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum Error {
    /// Unable to encrypt a plain text outside of the valid range.
    #[cfg_attr(
        feature = "std",
        error("Unable to encrypt a plain text outside of the valid range")
    )]
    PlainTextRangeError,

    /// Encrypted value was not found within the valid range.
    #[cfg_attr(
        feature = "std",
        error("Encrypted value was not found within the valid range")
    )]
    CipherTextDecryptionError,

    /// Too many auditors.
    #[cfg_attr(
        feature = "std",
        error("The number of auditors is over the MAX_AUDITORS limit")
    )]
    TooManyAuditors,

    /// Wrong number of auditors.
    #[cfg_attr(
        feature = "std",
        error("The number of auditor keys doesn't match the number of auditors in the proof")
    )]
    WrongNumberOfAuditors,

    /// A proof verification error occurred.
    #[cfg_attr(feature = "std", error("A proof verification error occurred"))]
    VerificationError,

    /// Failed to verify a correctness proof.
    #[cfg_attr(
        feature = "std",
        error("Failed to verify the check number {check} of the correctness proof")
    )]
    CorrectnessFinalResponseVerificationError { check: u16 },

    /// Failed to verify a wellformedness proof.
    #[cfg_attr(
        feature = "std",
        error("Failed to verify the check number {check} of the wellformedness proof")
    )]
    WellformednessFinalResponseVerificationError { check: u16 },

    /// Failed to verify a ciphertext refreshment proof.
    #[cfg_attr(
        feature = "std",
        error("Failed to verify the check number {check} of the ciphertext refreshment proof")
    )]
    CiphertextRefreshmentFinalResponseVerificationError { check: u16 },

    /// Failed to verify an encrypting the same value proof.
    #[cfg_attr(
        feature = "std",
        error("Failed to verify the check number {check} of the encrypting the same value proof")
    )]
    EncryptingSameValueFinalResponseVerificationError { check: u16 },

    /// Failed to verify a ciphertext the same value proof.
    #[cfg_attr(
        feature = "std",
        error("Failed to verify the check number {check} of the ciphertext same value proof")
    )]
    CiphertextSameValueFinalResponseVerificationError { check: u16 },

    /// Elements set is empty.
    #[cfg_attr(
        feature = "std",
        error("The elements set passed to the membership proof cannot be empty.")
    )]
    EmptyElementsSet,

    /// Invalid exponent parameter was passed.
    #[cfg_attr(feature = "std", error("Invalid exponent parameter was passed."))]
    InvalidExponentParameter,

    /// The amount in the initial transaction does not match the amount that receiver expected.
    #[cfg_attr(
        feature = "std",
        error("Expected to receive {expected_amount:?} from the sender,) got a different amount.")
    )]
    TransactionAmountMismatch { expected_amount: Balance },

    /// The public key in the memo of the initial transaction does not match the public key
    /// in the memo.
    #[cfg_attr(
        feature = "std",
        error("Public keys in the memo and the account are different.")
    )]
    InputPubKeyMismatch,

    /// The sender has attempted to send more that their balance.
    #[cfg_attr(
        feature = "std",
        error("Transaction amount {transaction_amount} must be less than or equal to {balance}")
    )]
    NotEnoughFund {
        balance: Balance,
        transaction_amount: Balance,
    },

    /// The account Id in the transaction does not match the input account info.
    #[cfg_attr(
        feature = "std",
        error("The account does not match the account on the transaction")
    )]
    ElgamalKeysIdMismatch,

    /// The mercat transaction id does not match the one supplied previously.
    #[cfg_attr(
        feature = "std",
        error("The mercat transaction id does not match the one supplied previously.")
    )]
    TransactionIdMismatch,

    /// Error while converting a transaction content to binary format.
    #[cfg_attr(
        feature = "std",
        error("Error during the serialization to byte array.")
    )]
    SerializationError,

    /// A range proof error occurred.
    #[cfg_attr(feature = "std", error(transparent))]
    BulletproofProvingError(bulletproofs::ProofError),

    /// The auditor failed to verify confidential transaction.
    #[cfg_attr(
        feature = "std",
        error("The auditor failed to verify confidential transaction.")
    )]
    AuditorVerifyError,
}

impl From<bulletproofs::ProofError> for Error {
    fn from(err: bulletproofs::ProofError) -> Self {
        Self::BulletproofProvingError(err)
    }
}

pub type Result<T, E = Error> = sp_std::result::Result<T, E>;
