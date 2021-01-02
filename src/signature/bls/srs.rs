use super::BLSSignatureScheme;
use crate::signature::utils::errors::SignatureError;
use algebra::{
    AffineCurve, CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
};
use rand::Rng;

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize, Clone, PartialEq)]
pub struct SRS<B: BLSSignatureScheme> {
    pub g_public_key: B::PublicKeyGroup,
    pub g_signature: B::SignatureGroup,
}

impl<B: BLSSignatureScheme> SRS<B> {
    pub fn setup<R: Rng>(_: &mut R) -> Result<Self, SignatureError> {
        let srs = Self {
            g_public_key: B::PublicKeyGroup::prime_subgroup_generator(),
            g_signature: B::SignatureGroup::prime_subgroup_generator(),
        };
        Ok(srs)
    }
}
