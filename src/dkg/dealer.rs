use crate::{dkg::participant::Participant, signature::scheme::BatchVerifiableSignatureScheme};
use algebra::PairingEngine;

#[derive(Clone)]
pub struct Dealer<
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
> {
    pub private_key_sig: SSIG::Secret,
    pub accumulated_secret: E::G2Affine,
    pub participant: Participant<E, SSIG>,
}
