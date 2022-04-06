use crate::signature::scheme::BatchVerifiableSignatureScheme;
use ark_ec::PairingEngine;

#[derive(Clone)]
pub enum ParticipantState {
    Dealer,
    DealerShared,

    Initial,
    Verified,
}

// #[derive(Clone)]
pub struct Participant<
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
> {
    pub pairing_type: std::marker::PhantomData<E>,
    pub id: usize,
    pub public_key_sig: SSIG::PublicKey,
    pub state: ParticipantState,
}

impl<
        E: PairingEngine,
        SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    > Clone for Participant<E, SSIG>
{
    fn clone(&self) -> Self {
        Participant {
            pairing_type: self.pairing_type.clone(),
            id: self.id.clone(),
            public_key_sig: self.public_key_sig.clone(),
            state: self.state.clone(),
        }
    }
}
