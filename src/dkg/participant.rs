use crate::signature::scheme::BatchVerifiableSignatureScheme;
use ark_ec::PairingEngine;

#[derive(Clone)]
pub enum ParticipantState {
    Dealer,
    DealerShared,

    Initial,
    Verified,
}

#[derive(Clone)]
pub struct Participant<
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
> {
    pub pairing_type: std::marker::PhantomData<E>,
    pub id: usize,
    pub public_key_sig: SSIG::PublicKey,
    pub state: ParticipantState,
}
