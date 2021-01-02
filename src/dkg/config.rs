use super::srs::SRS;
use algebra::PairingEngine;

#[derive(Clone)]
pub struct Config<E: PairingEngine> {
    pub srs: SRS<E>,
    pub u_1: E::G2Affine,
    pub degree: usize,
}
