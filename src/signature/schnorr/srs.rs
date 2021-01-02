use crate::signature::utils::errors::SignatureError;
use algebra::{
    AffineCurve, CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write,
};
use rand::Rng;

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize, Clone, PartialEq)]
pub struct SRS<C: AffineCurve> {
    pub g_public_key: C,
}

impl<C: AffineCurve> SRS<C> {
    pub fn setup<R: Rng>(_: &mut R) -> Result<Self, SignatureError> {
        let srs = Self {
            g_public_key: C::prime_subgroup_generator(),
        };
        Ok(srs)
    }
}
