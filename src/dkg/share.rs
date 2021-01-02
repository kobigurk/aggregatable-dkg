use crate::{
    dkg::{errors::DKGError, pvss::PVSSShare},
    signature::scheme::BatchVerifiableSignatureScheme,
};
use algebra::{
    BTreeMap, CanonicalDeserialize, CanonicalSerialize, PairingEngine, Read, SerializationError,
    Write,
};
use std::io::Cursor;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct DKGShare<
    E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
> {
    pub participant_id: usize,
    pub pvss_share: PVSSShare<E>,
    pub c_i: E::G1Affine,
    pub c_i_pok: SPOK::Signature,
    pub signature_on_c_i: SSIG::Signature,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct DKGTranscriptParticipant<
    E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
> {
    pub c_i: E::G1Affine,
    pub weight: u64,
    pub c_i_pok: SPOK::Signature,
    pub signature_on_c_i: SSIG::Signature,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct DKGTranscript<
    E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
> {
    pub degree: usize,
    pub num_participants: usize,
    pub contributions: BTreeMap<usize, DKGTranscriptParticipant<E, SPOK, SSIG>>,
    pub pvss_share: PVSSShare<E>,
}

pub fn message_from_c_i<E: PairingEngine>(c_i: E::G1Affine) -> Result<Vec<u8>, DKGError<E>> {
    let mut message_writer = Cursor::new(vec![]);
    c_i.serialize(&mut message_writer)?;
    Ok(message_writer.get_ref().to_vec())
}

impl<
        E: PairingEngine,
        SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
        SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
    > DKGTranscript<E, SPOK, SSIG>
{
    pub fn empty(degree: usize, num_participants: usize) -> Self {
        Self {
            degree,
            num_participants,
            contributions: BTreeMap::new(),
            pvss_share: PVSSShare::empty(degree, num_participants),
        }
    }

    pub fn aggregate(&self, other: &Self) -> Result<Self, DKGError<E>> {
        if self.degree != other.degree || self.num_participants != other.num_participants {
            return Err(DKGError::TranscriptDifferentConfig(
                self.degree,
                other.degree,
                self.num_participants,
                other.num_participants,
            ));
        }
        let contributions = (0..self.num_participants)
            .map(
                |i| match (self.contributions.get(&i), other.contributions.get(&i)) {
                    (Some(a), Some(b)) => {
                        if a.c_i != b.c_i {
                            return Err(DKGError::TranscriptDifferentCommitments);
                        }
                        let transcript_participant = DKGTranscriptParticipant {
                            c_i: a.c_i,
                            weight: a.weight + b.weight,
                            c_i_pok: a.c_i_pok.clone(),
                            signature_on_c_i: a.signature_on_c_i.clone(),
                        };
                        Ok(Some((i, transcript_participant)))
                    }
                    (Some(a), None) => Ok(Some((i, a.clone()))),
                    (None, Some(b)) => Ok(Some((i, b.clone()))),
                    (None, None) => Ok(None),
                },
            )
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|e| e)
            .collect::<Vec<_>>();
        let aggregated = Self {
            degree: self.degree,
            num_participants: self.num_participants,
            contributions: contributions.into_iter().collect(),
            pvss_share: self.pvss_share.aggregate(&other.pvss_share),
        };
        Ok(aggregated)
    }
}
