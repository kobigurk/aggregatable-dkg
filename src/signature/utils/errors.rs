use std::fmt::Display;
use thiserror::Error;

#[derive(Debug)]
pub enum VerifyProofEquation {
    Eq1,
    Eq2,
    Eq3,
    EqAllProbabilistic,
    EqProbabilistic,
}

impl Display for VerifyProofEquation {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        match *self {
            VerifyProofEquation::Eq1 => f.write_str("Eq1"),
            VerifyProofEquation::Eq2 => f.write_str("Eq2"),
            VerifyProofEquation::Eq3 => f.write_str("Eq3"),
            VerifyProofEquation::EqAllProbabilistic => f.write_str("EqAllProbabilistic"),
            VerifyProofEquation::EqProbabilistic => f.write_str("EqProbabilistic"),
        }
    }
}

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Could not generate SRS")]
    SRSSetupError,
    #[error("Failed verifying equation `{0}`")]
    AlgebraicVerifyProof(VerifyProofEquation),
    #[error("Failed verifying BLS equation")]
    BLSVerify,
    #[error("Failed verifying Schnorr equation")]
    SchnorrVerify,
    #[error("Signature doesn't have an inverse")]
    SignatureDoesNotHaveInverse,
    #[error("SRS is different")]
    SRSDifferent,
    #[error("SerializationError: {0}")]
    SerializationError(#[from] algebra::SerializationError),
    #[error("Different lengths in batch verification: {0}, {1}, {2}")]
    BatchVerification(usize, usize, usize),
}
