use super::{
    public_key::{KeyProof, ProvenPublicKey, PublicKey},
    signature::{Signature, SignatureProof},
    srs::SRS,
    PERSONALIZATION,
};
use crate::signature::utils::{errors::SignatureError, hash::hash_to_group};
use algebra::{
    AffineCurve, CanonicalDeserialize, CanonicalSerialize, PairingEngine, ProjectiveCurve, Read,
    SerializationError, UniformRand, Write,
};
use rand::Rng;
use std::ops::Neg;

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PrivateKey<E: PairingEngine> {
    pub sk: E::G2Affine,
}

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Keypair<E: PairingEngine> {
    pub srs: SRS<E>,
    pub alpha: E::Fr,
    pub beta: E::Fr,
    pub private: PrivateKey<E>,
    pub public: PublicKey<E>,
}

impl<E: PairingEngine> Keypair<E> {
    pub fn generate_keypair<R: Rng>(rng: &mut R, srs: SRS<E>) -> Result<Self, SignatureError> {
        let a = E::Fr::rand(rng);
        let a_g2 = srs.g_1_g2.mul(a.clone());
        let private_key = PrivateKey {
            sk: a_g2.into_affine(),
        };
        let a_g1 = srs.h_g1.mul(a);
        let public_key = PublicKey {
            srs: srs.clone(),
            pk: a_g1.into_affine(),
        };
        let keypair = Keypair {
            alpha: E::Fr::rand(rng),
            beta: E::Fr::rand(rng),
            srs: srs.clone(),
            private: private_key,
            public: public_key,
        };
        Ok(keypair)
    }

    pub fn refresh_randomness<R: Rng>(&self, rng: &mut R) -> Result<Self, SignatureError> {
        let keypair = Keypair {
            alpha: E::Fr::rand(rng),
            beta: E::Fr::rand(rng),
            srs: self.srs.clone(),
            private: self.private.clone(),
            public: self.public.clone(),
        };
        Ok(keypair)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature<E>, SignatureError> {
        let hashed_message = hash_to_group::<E::G1Affine>(PERSONALIZATION, message)?;
        let signature_proof = self.prove_signature(hashed_message)?;

        let signature = Signature { signature_proof };

        Ok(signature)
    }

    pub fn prove_key(&self) -> Result<ProvenPublicKey<E>, SignatureError> {
        let pi_1_g2 = self.srs.g_1_g2.mul(self.alpha.neg()) + &self.srs.g_2_g2.mul(self.beta.neg());
        let pi_2_g2 = self.srs.g_3_g2.mul(self.alpha.neg())
            + &self.srs.g_4_g2.mul(self.beta.neg())
            + &self.private.sk.into_projective();
        let pi_1_g1 = self.srs.h_g1.mul(self.alpha.clone());
        let pi_3_g1 = self.srs.h_g1.mul(self.beta.clone());

        let key_proof = KeyProof {
            pi_1_g2: pi_1_g2.into_affine(),
            pi_2_g2: pi_2_g2.into_affine(),
            pi_1_g1: pi_1_g1.into_affine(),
            pi_3_g1: pi_3_g1.into_affine(),
        };

        let proven_public_key = ProvenPublicKey {
            public_key: self.public.clone(),
            key_proof,
        };
        Ok(proven_public_key)
    }

    fn prove_signature(
        &self,
        hashed_message: E::G1Projective,
    ) -> Result<SignatureProof<E>, SignatureError> {
        let pi_2_g1 = hashed_message.mul(self.alpha.clone());
        let pi_4_g1 = hashed_message.mul(self.beta.clone());

        let signature_proof = SignatureProof {
            pi_2_g1: pi_2_g1.into_affine(),
            pi_4_g1: pi_4_g1.into_affine(),
        };

        Ok(signature_proof)
    }
}
