use super::srs::SRS;
use crate::signature::utils::errors::{SignatureError, VerifyProofEquation};
use algebra::{
    AffineCurve, CanonicalDeserialize, CanonicalSerialize, One, PairingEngine, PrimeField,
    ProjectiveCurve, Read, SerializationError, UniformRand, Write, Zero,
};
use rand::Rng;
use std::ops::Neg;

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<E: PairingEngine> {
    pub srs: SRS<E>,
    pub pk: E::G1Affine,
}

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvenPublicKey<E: PairingEngine> {
    pub public_key: PublicKey<E>,
    pub key_proof: KeyProof<E>,
}

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeyProof<E: PairingEngine> {
    pub pi_1_g2: E::G2Affine,
    pub pi_2_g2: E::G2Affine,
    pub pi_1_g1: E::G1Affine,
    pub pi_3_g1: E::G1Affine,
}

impl<E: PairingEngine> ProvenPublicKey<E> {
    pub fn aggregate(public_keys: &[Self], srs: SRS<E>) -> Result<Self, SignatureError> {
        let zero_proven_public_key = Self {
            public_key: PublicKey {
                srs,
                pk: E::G1Affine::zero(),
            },
            key_proof: KeyProof {
                pi_1_g2: E::G2Affine::zero(),
                pi_2_g2: E::G2Affine::zero(),
                pi_1_g1: E::G1Affine::zero(),
                pi_3_g1: E::G1Affine::zero(),
            },
        };
        let aggregated_public_key =
            public_keys
                .into_iter()
                .try_fold(zero_proven_public_key, |acc, pk| {
                    if acc.public_key.srs != pk.public_key.srs {
                        return Err(SignatureError::SRSDifferent);
                    }
                    Ok(ProvenPublicKey {
                        public_key: PublicKey {
                            srs: acc.public_key.srs,
                            pk: acc.public_key.pk + pk.public_key.pk.clone(),
                        },
                        key_proof: KeyProof {
                            pi_1_g2: acc.key_proof.pi_1_g2 + pk.key_proof.pi_1_g2.clone(),
                            pi_2_g2: acc.key_proof.pi_2_g2 + pk.key_proof.pi_2_g2.clone(),
                            pi_1_g1: acc.key_proof.pi_1_g1 + pk.key_proof.pi_1_g1.clone(),
                            pi_3_g1: acc.key_proof.pi_3_g1 + pk.key_proof.pi_3_g1.clone(),
                        },
                    })
                })?;

        Ok(aggregated_public_key)
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        let eq1 = vec![
            (
                self.public_key.srs.h_g1.into(),
                self.key_proof.pi_1_g2.into(),
            ),
            (
                self.key_proof.pi_1_g1.into(),
                self.public_key.srs.g_1_g2.into(),
            ),
            (
                self.key_proof.pi_3_g1.into(),
                self.public_key.srs.g_2_g2.into(),
            ),
        ];
        if !E::product_of_pairings(eq1.iter()).is_one() {
            return Err(SignatureError::AlgebraicVerifyProof(
                VerifyProofEquation::Eq1,
            ));
        }
        let eq3 = vec![
            (
                self.public_key.srs.h_g1.into(),
                self.key_proof.pi_2_g2.into(),
            ),
            (
                self.key_proof.pi_1_g1.into(),
                self.public_key.srs.g_3_g2.into(),
            ),
            (
                self.key_proof.pi_3_g1.into(),
                self.public_key.srs.g_4_g2.into(),
            ),
            (
                self.public_key.pk.into(),
                self.public_key.srs.g_1_g2.neg().into(),
            ),
        ];
        if !E::product_of_pairings(eq3.iter()).is_one() {
            return Err(SignatureError::AlgebraicVerifyProof(
                VerifyProofEquation::Eq3,
            ));
        }

        Ok(())
    }

    pub fn verify_probabilistically<R: Rng>(&self, rng: &mut R) -> Result<(), SignatureError> {
        let r = E::Fr::rand(rng);
        let eq = vec![
            (
                self.public_key
                    .srs
                    .h_g1
                    .mul(r.into_repr())
                    .into_affine()
                    .into(),
                self.key_proof.pi_1_g2.into(),
            ),
            (
                (self.public_key.pk.neg().into_projective()
                    + &self.key_proof.pi_1_g1.mul(r.into_repr()))
                    .into_affine()
                    .into(),
                self.public_key.srs.g_1_g2.into(),
            ),
            (
                self.key_proof
                    .pi_3_g1
                    .mul(r.into_repr())
                    .into_affine()
                    .into(),
                self.public_key.srs.g_2_g2.into(),
            ),
            (
                self.public_key.srs.h_g1.into(),
                self.key_proof.pi_2_g2.into(),
            ),
            (
                self.key_proof.pi_1_g1.into(),
                self.public_key.srs.g_3_g2.into(),
            ),
            (
                self.key_proof.pi_3_g1.into(),
                self.public_key.srs.g_4_g2.into(),
            ),
        ];
        if !E::product_of_pairings(eq.iter()).is_one() {
            return Err(SignatureError::AlgebraicVerifyProof(
                VerifyProofEquation::EqProbabilistic,
            ));
        }

        Ok(())
    }
}
