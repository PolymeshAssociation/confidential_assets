use bulletproofs::ProofError;

use sp_std::{fmt, result::Result};

use crate::Balance;

/// Represents an error resulted from asset value encryption,
/// decryption, or proof generation.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    #[inline]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl From<ErrorKind> for Error {
    #[inline]
    fn from(kind: ErrorKind) -> Error {
        Error { kind }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ErrorKind::*;
        match &self.kind {
            PlainTextRangeError => {
                write!(
                    f,
                    "Unable to encrypt a plain text outside of the valid range"
                )
            }
            CipherTextDecryptionError => {
                write!(f, "Encrypted value was not found within the valid range")
            }
            VerificationError => {
                write!(f, "A proof verification error occurred")
            }
            CorrectnessFinalResponseVerificationError { check } => {
                write!(
                    f,
                    "Failed to verify the check number {} of the correctness proof",
                    check
                )
            }
            WellformednessFinalResponseVerificationError { check } => {
                write!(
                    f,
                    "Failed to verify the check number {} of the wellformedness proof",
                    check
                )
            }
            CiphertextRefreshmentFinalResponseVerificationError { check } => {
                write!(
                    f,
                    "Failed to verify the check number {} of the ciphertext refreshment proof",
                    check
                )
            }
            EncryptingSameValueFinalResponseVerificationError { check } => {
                write!(
                    f,
                    "Failed to verify the check number {} of the encrypting the same value proof",
                    check
                )
            }
            EmptyElementsSet => {
                write!(
                    f,
                    "The elements set passed to the membership proof cannot be empty."
                )
            }
            InvalidExponentParameter => {
                write!(f, "Invalid exponent parameter was passed.")
            }
            TransactionAmountMismatch { expected_amount } => {
                write!(
                    f,
                    "Expected to receive {:?} from the sender,) got a different amount.",
                    expected_amount
                )
            }
            InputPubKeyMismatch => {
                write!(f, "Public keys in the memo and the account are different.")
            }
            NotEnoughFund {
                balance,
                transaction_amount,
            } => {
                write!(
                    f,
                    "Transaction amount {} must be less than or equal to {}",
                    transaction_amount, balance
                )
            }
            AccountIdMismatch => {
                write!(
                    f,
                    "The account does not match the account on the transaction"
                )
            }
            TransactionIdMismatch => {
                write!(
                    f,
                    "The mercat transaction id does not match the one supplied previously."
                )
            }
            SerializationError => {
                write!(f, "Error during the serialization to byte array.")
            }
            ProvingError { source } => {
                write!(f, "A range proof error occurred: {:?}", source)
            }
            AuditorPayloadError => {
                write!(
                    f,
                    "The auditors' payload does not match the compliance rules."
                )
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Unable to encrypt a plain text outside of the valid range.
    PlainTextRangeError,

    /// Encrypted value was not found within the valid range.
    CipherTextDecryptionError,

    /// A proof verification error occurred.
    VerificationError,

    /// Failed to verify a correctness proof.
    CorrectnessFinalResponseVerificationError { check: u16 },

    /// Failed to verify a wellformedness proof.
    WellformednessFinalResponseVerificationError { check: u16 },

    /// Failed to verify a ciphertext refreshment proof.
    CiphertextRefreshmentFinalResponseVerificationError { check: u16 },

    /// Failed to verify an encrypting the same value proof.
    EncryptingSameValueFinalResponseVerificationError { check: u16 },

    /// Elements set is empty.
    EmptyElementsSet,

    /// Invalid exponent parameter was passed.
    InvalidExponentParameter,

    /// The amount in the initial transaction does not match the amount that receiver expected.
    TransactionAmountMismatch { expected_amount: Balance },

    /// The public key in the memo of the initial transaction does not match the public key
    /// in the memo.
    InputPubKeyMismatch,

    /// The sender has attempted to send more that their balance.
    NotEnoughFund {
        balance: Balance,
        transaction_amount: Balance,
    },

    /// The account Id in the transaction does not match the input account info.
    AccountIdMismatch,

    /// The mercat transaction id does not match the one supplied previously.
    TransactionIdMismatch,

    /// Error while converting a transaction content to binary format.
    SerializationError,

    /// A range proof error occurred.
    ProvingError { source: ProofError },

    /// The auditors' payload does not match the compliance rules.
    AuditorPayloadError,
}

pub type Fallible<T, E = Error> = Result<T, E>;
