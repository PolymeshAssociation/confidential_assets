//! The TranscriptProtocol implementation for a Merlin transcript.
//!
//! The role of a Merlin transcript in a non-interactive zero knowledge
//! proof system is to provide a challenge without revealing any information
//! about the secrets while protecting against Chosen Message attacks.

use crate::{
    elgamal::CommitmentWitness,
    errors::{Error, Result},
    proofs::encryption_proofs::{ZKPChallenge, ENCRYPTION_PROOFS_CHALLENGE_LABEL},
};

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};

use sp_std::convert::TryInto;

pub trait TranscriptProtocol {
    /// If the inputted message is not trivial append it to the
    /// transcript's state.
    ///
    /// # Inputs
    /// * `label`   a domain label for the point to append.
    /// * `message` a compressed Ristretto point.
    ///
    /// # Output
    /// Ok on success, or an error on failure.
    fn append_validated_point(
        &mut self,
        label: &'static [u8],
        message: &CompressedRistretto,
    ) -> Result<()>;

    /// Appends a domain separator string to the transcript's state.
    ///
    /// # Inputs
    /// * `message` a message string.
    fn append_domain_separator(&mut self, message: &'static [u8]);

    /// Get the protocol's challenge.
    ///
    /// # Inputs
    /// * `label` a domain label.
    ///
    /// # Output
    /// A scalar challenge.
    fn scalar_challenge(&mut self, label: &'static [u8]) -> Result<ZKPChallenge>;

    /// Create an RNG seeded from the transcript's cloned state and
    /// randomness from an external `rng`.
    ///
    /// # Inputs
    /// * `rng` an external RNG.
    /// * `witness` a commitment witness which will be used to reseed the RNG.
    ///
    /// # Output
    /// A new RNG.
    fn create_transcript_rng_from_witness<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        witness: &CommitmentWitness,
    ) -> TranscriptRng;
}

impl TranscriptProtocol for Transcript {
    fn append_validated_point(
        &mut self,
        label: &'static [u8],
        message: &CompressedRistretto,
    ) -> Result<()> {
        use curve25519_dalek::traits::IsIdentity;

        ensure!(!message.is_identity(), Error::VerificationError);
        self.append_message(label, message.as_bytes());
        Ok(())
    }

    fn append_domain_separator(&mut self, message: &'static [u8]) {
        self.append_message(b"dom-sep", message)
    }

    fn scalar_challenge(&mut self, label: &'static [u8]) -> Result<ZKPChallenge> {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_mod_order_wide(&buf).try_into()
    }

    fn create_transcript_rng_from_witness<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        witness: &CommitmentWitness,
    ) -> TranscriptRng {
        self.build_rng()
            .rekey_with_witness_bytes(b"w_value", &witness.value().to_bytes())
            .rekey_with_witness_bytes(b"w_blinding", witness.blinding().as_bytes())
            .finalize(rng)
    }
}

/// A trait that is used to update the transcript with the initial message
/// that results from the first round of the protocol.
pub trait UpdateTranscript {
    fn challenge_label() -> &'static [u8] {
        ENCRYPTION_PROOFS_CHALLENGE_LABEL
    }

    fn update_transcript(&self, d: &mut Transcript) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_trivial_message() {
        use curve25519_dalek::ristretto::CompressedRistretto;
        let mut transcript = Transcript::new(b"unit test");
        assert_err!(
            transcript.append_validated_point(b"identity", &CompressedRistretto::default()),
            Error::VerificationError
        );
    }
}
