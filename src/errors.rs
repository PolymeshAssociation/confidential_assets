use thiserror::Error;

use crate::Balance;

/// Confidential asset error
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// Unable to encrypt a plain text outside of the valid range.
    #[error("Unable to encrypt a plain text outside of the valid range")]
    PlainTextRangeError,

    /// Encrypted value was not found within the valid range.
    #[error("Encrypted value was not found within the valid range")]
    CipherTextDecryptionError,

    /// A proof verification error occurred.
    #[error("A proof verification error occurred")]
    VerificationError,

    /// Failed to verify a correctness proof.
    #[error("Failed to verify the check number {check} of the correctness proof")]
    CorrectnessFinalResponseVerificationError { check: u16 },

    /// Failed to verify a wellformedness proof.
    #[error("Failed to verify the check number {check} of the wellformedness proof")]
    WellformednessFinalResponseVerificationError { check: u16 },

    /// Failed to verify a ciphertext refreshment proof.
    #[error("Failed to verify the check number {check} of the ciphertext refreshment proof")]
    CiphertextRefreshmentFinalResponseVerificationError { check: u16 },

    /// Failed to verify an encrypting the same value proof.
    #[error("Failed to verify the check number {check} of the encrypting the same value proof")]
    EncryptingSameValueFinalResponseVerificationError { check: u16 },

    /// Failed to verify a ciphertext the same value proof.
    #[error("Failed to verify the check number {check} of the ciphertext same value proof")]
    CiphertextSameValueFinalResponseVerificationError { check: u16 },

    /// Elements set is empty.
    #[error("The elements set passed to the membership proof cannot be empty.")]
    EmptyElementsSet,

    /// Invalid exponent parameter was passed.
    #[error("Invalid exponent parameter was passed.")]
    InvalidExponentParameter,

    /// The amount in the initial transaction does not match the amount that receiver expected.
    #[error("Expected to receive {expected_amount:?} from the sender,) got a different amount.")]
    TransactionAmountMismatch { expected_amount: Balance },

    /// The public key in the memo of the initial transaction does not match the public key
    /// in the memo.
    #[error("Public keys in the memo and the account are different.")]
    InputPubKeyMismatch,

    /// The sender has attempted to send more that their balance.
    #[error("Transaction amount {transaction_amount} must be less than or equal to {balance}")]
    NotEnoughFund {
        balance: Balance,
        transaction_amount: Balance,
    },

    /// The account Id in the transaction does not match the input account info.
    #[error("The account does not match the account on the transaction")]
    ElgamalKeysIdMismatch,

    /// The mercat transaction id does not match the one supplied previously.
    #[error("The mercat transaction id does not match the one supplied previously.")]
    TransactionIdMismatch,

    /// Error while converting a transaction content to binary format.
    #[error("Error during the serialization to byte array.")]
    SerializationError,

    /// A range proof error occurred.
    #[error(transparent)]
    BulletproofProvingError(#[from] bulletproofs::ProofError),

    /// The auditors' payload does not match the compliance rules.
    #[error("The auditors' payload does not match the compliance rules.")]
    AuditorPayloadError,
}

pub type Result<T, E = Error> = sp_std::result::Result<T, E>;
