use crate::signature::utils::errors::SignatureError;
use ark_ec::AffineCurve;
use ark_ff::{PrimeField, Zero};
use blake2s_simd::Params;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

fn rng_from_message(personalization: &[u8], message: &[u8]) -> ChaChaRng {
    let hash = Params::new()
        .hash_length(32)
        .personal(personalization)
        .to_state()
        .update(message)
        .finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(hash.as_bytes());
    let rng = ChaChaRng::from_seed(seed);
    rng
}

pub fn hash_to_group<C: AffineCurve>(
    personalization: &[u8],
    message: &[u8],
) -> Result<C::Projective, SignatureError> {
    let mut rng = rng_from_message(personalization, message);
    loop {
        let bytes: Vec<u8> = (0..C::zero().serialized_size())
            .map(|_| rng.gen())
            .collect();
        if let Some(p) = C::from_random_bytes(&bytes) {
            let scaled = p.mul_by_cofactor_to_projective();
            if !scaled.is_zero() {
                return Ok(scaled);
            }
        }
    }
}

pub fn hash_to_field<F: PrimeField>(
    personalization: &[u8],
    message: &[u8],
) -> Result<F, SignatureError> {
    let mut rng = rng_from_message(personalization, message);
    loop {
        let bytes: Vec<u8> = (0..F::zero().serialized_size())
            .map(|_| rng.gen())
            .collect();
        if let Some(p) = F::from_random_bytes(&bytes) {
            return Ok(p);
        }
    }
}
