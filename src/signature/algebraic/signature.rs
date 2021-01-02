use algebra::{
    AffineCurve, CanonicalDeserialize, CanonicalSerialize, One, PairingEngine, PrimeField,
    ProjectiveCurve, Read, SerializationError, UniformRand, Write, Zero,
};

use super::{public_key::ProvenPublicKey, PERSONALIZATION};
use crate::signature::utils::{
    errors::{SignatureError, VerifyProofEquation},
    hash::hash_to_group,
};
use rand::Rng;
use std::ops::Neg;

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<E: PairingEngine> {
    pub signature_proof: SignatureProof<E>,
}

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SignatureProof<E: PairingEngine> {
    pub pi_2_g1: E::G1Affine,
    pub pi_4_g1: E::G1Affine,
}

impl<E: PairingEngine> Default for Signature<E> {
    fn default() -> Self {
        Signature {
            signature_proof: SignatureProof {
                pi_2_g1: E::G1Affine::zero(),
                pi_4_g1: E::G1Affine::zero(),
            },
        }
    }
}

impl<E: PairingEngine> Signature<E> {
    pub fn verify_and_derive(
        &self,
        public_key: ProvenPublicKey<E>,
        message: &[u8],
    ) -> Result<E::Fqk, SignatureError> {
        let hashed_message = hash_to_group::<E::G1Affine>(PERSONALIZATION, message)?;
        self.verify_proof(public_key.clone(), hashed_message)?;

        self.derive(public_key, message)
    }

    pub fn verify(
        &self,
        public_key: ProvenPublicKey<E>,
        message: &[u8],
    ) -> Result<(), SignatureError> {
        let hashed_message = hash_to_group::<E::G1Affine>(PERSONALIZATION, message)?;
        self.verify_proof(public_key.clone(), hashed_message)
    }

    pub fn derive(
        &self,
        public_key: ProvenPublicKey<E>,
        message: &[u8],
    ) -> Result<E::Fqk, SignatureError> {
        let hashed_message = hash_to_group::<E::G1Affine>(PERSONALIZATION, message)?;
        let sig_elements = vec![
            (
                hashed_message.into_affine().into(),
                public_key.key_proof.pi_2_g2.into(),
            ),
            (
                self.signature_proof.pi_2_g1.into(),
                public_key.public_key.srs.g_3_g2.into(),
            ),
            (
                self.signature_proof.pi_4_g1.into(),
                public_key.public_key.srs.g_4_g2.into(),
            ),
        ];
        let sig = E::product_of_pairings(sig_elements.iter());

        Ok(sig)
    }

    fn verify_proof(
        &self,
        public_key: ProvenPublicKey<E>,
        hashed_message: E::G1Projective,
    ) -> Result<(), SignatureError> {
        let eq2 = vec![
            (
                hashed_message.into_affine().into(),
                public_key.key_proof.pi_1_g2.into(),
            ),
            (
                self.signature_proof.pi_2_g1.into(),
                public_key.public_key.srs.g_1_g2.into(),
            ),
            (
                self.signature_proof.pi_4_g1.into(),
                public_key.public_key.srs.g_2_g2.into(),
            ),
        ];
        if !E::product_of_pairings(eq2.iter()).is_one() {
            return Err(SignatureError::AlgebraicVerifyProof(
                VerifyProofEquation::Eq2,
            ));
        }

        Ok(())
    }

    pub fn verify_all_probabilistically<R: Rng>(
        &self,
        rng: &mut R,
        public_key: ProvenPublicKey<E>,
        message: &[u8],
    ) -> Result<(), SignatureError> {
        let hashed_message = hash_to_group::<E::G1Affine>(PERSONALIZATION, message)?;
        let r = E::Fr::rand(rng);
        let r2 = E::Fr::rand(rng);
        let eq = vec![
            (
                (hashed_message.into_affine().mul(r2.into_repr())
                    + &public_key.public_key.srs.h_g1.mul(r.into_repr()))
                    .into_affine()
                    .into(),
                public_key.key_proof.pi_1_g2.into(),
            ),
            (
                (public_key.public_key.pk.neg().into_projective()
                    + &self.signature_proof.pi_2_g1.mul(r2.into_repr())
                    + &public_key.key_proof.pi_1_g1.mul(r.into_repr()))
                    .into_affine()
                    .into(),
                public_key.public_key.srs.g_1_g2.into(),
            ),
            (
                (self.signature_proof.pi_4_g1.mul(r2.into_repr())
                    + &public_key.key_proof.pi_3_g1.mul(r.into_repr()))
                    .into_affine()
                    .into(),
                public_key.public_key.srs.g_2_g2.into(),
            ),
            (
                public_key.public_key.srs.h_g1.into(),
                public_key.key_proof.pi_2_g2.into(),
            ),
            (
                public_key.key_proof.pi_1_g1.into(),
                public_key.public_key.srs.g_3_g2.into(),
            ),
            (
                public_key.key_proof.pi_3_g1.into(),
                public_key.public_key.srs.g_4_g2.into(),
            ),
        ];
        if !E::product_of_pairings(eq.iter()).is_one() {
            return Err(SignatureError::AlgebraicVerifyProof(
                VerifyProofEquation::EqAllProbabilistic,
            ));
        }

        Ok(())
    }

    pub fn aggregate(signatures: &[Self]) -> Result<Self, SignatureError> {
        let aggregated_signature =
            signatures
                .into_iter()
                .fold(Self::default(), |acc, s| Signature {
                    signature_proof: SignatureProof {
                        pi_2_g1: acc.signature_proof.pi_2_g1 + s.signature_proof.pi_2_g1.clone(),
                        pi_4_g1: acc.signature_proof.pi_4_g1 + s.signature_proof.pi_4_g1.clone(),
                    },
                });
        Ok(aggregated_signature)
    }
}
