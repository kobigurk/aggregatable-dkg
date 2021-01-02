use crate::signature::utils::errors::SignatureError;
use algebra::{PairingEngine, SerializationError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DKGError<E: PairingEngine> {
    #[error("Ratio incorrect")]
    RatioIncorrect,
    #[error("Evaluations are wrong: product = {0}")]
    EvaluationsCheckError(E::G1Affine),
    #[error("Could not generate evaluation domain")]
    EvaluationDomainError,
    #[error("Config, dealer and nodes had different SRSes")]
    DifferentSRS,
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Invalid participant ID: {0}")]
    InvalidParticipantId(usize),
    #[error("Transcripts have different degree or number of participants: self.degree={0}, other.degree={1}, self.num_participants={2}, self.num_participants={3}")]
    TranscriptDifferentConfig(usize, usize, usize, usize),
    #[error("Transcripts have different commitments")]
    TranscriptDifferentCommitments,
}
