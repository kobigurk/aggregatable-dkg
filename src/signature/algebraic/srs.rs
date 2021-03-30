use crate::signature::utils::errors::SignatureError;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use rand::Rng;

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SRS<E: PairingEngine> {
    pub g_1_g2: E::G2Affine,
    pub h_g1: E::G1Affine,

    pub g_2_g2: E::G2Affine,
    pub g_3_g2: E::G2Affine,
    pub g_4_g2: E::G2Affine,
}

impl<E: PairingEngine> SRS<E> {
    pub fn setup<R: Rng>(rng: &mut R) -> Result<Self, SignatureError> {
        let srs = Self {
            g_1_g2: E::G2Affine::prime_subgroup_generator(),
            h_g1: E::G1Affine::prime_subgroup_generator(),

            g_2_g2: E::G2Projective::rand(rng).into_affine(),
            g_3_g2: E::G2Projective::rand(rng).into_affine(),
            g_4_g2: E::G2Projective::rand(rng).into_affine(),
        };
        Ok(srs)
    }
}
