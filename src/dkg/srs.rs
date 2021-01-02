use crate::dkg::errors::DKGError;
use algebra::{PairingEngine, ProjectiveCurve, UniformRand};
use rand::Rng;

#[derive(Clone)]
pub struct SRS<E: PairingEngine> {
    pub g_g1: E::G1Affine,
    pub h_g2: E::G2Affine,
}

impl<E: PairingEngine> SRS<E> {
    pub fn setup<R: Rng>(rng: &mut R) -> Result<Self, DKGError<E>> {
        Ok(Self {
            g_g1: E::G1Projective::rand(rng).into_affine(),
            h_g2: E::G2Projective::rand(rng).into_affine(),
        })
    }
}
