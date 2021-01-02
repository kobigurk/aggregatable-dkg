use crate::signature::utils::errors::SignatureError;
use algebra_core::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use std::fmt::Debug;

pub trait SignatureScheme: Debug + Clone + PartialEq + Sized {
    type SRS: Clone;
    type Secret;
    type PublicKey: Clone + CanonicalSerialize + CanonicalDeserialize;
    type Signature: Clone + CanonicalSerialize + CanonicalDeserialize;

    fn from_srs(srs: Self::SRS) -> Result<Self, SignatureError>;
    fn generate_keypair<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Secret, Self::PublicKey), SignatureError>;
    fn from_sk(&self, sk: &Self::Secret)
        -> Result<(Self::Secret, Self::PublicKey), SignatureError>;
    fn sign<R: Rng>(
        &self,
        rng: &mut R,
        sk: &Self::Secret,
        message: &[u8],
    ) -> Result<Self::Signature, SignatureError>;
    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureError>;
}

pub trait AggregatableSignatureScheme: SignatureScheme {
    fn aggregate_public_keys(
        &self,
        public_keys: &[&Self::PublicKey],
    ) -> Result<Self::PublicKey, SignatureError>;
    fn aggregate_signatures(
        &self,
        signatures: &[&Self::Signature],
    ) -> Result<Self::Signature, SignatureError>;
}

pub trait BatchVerifiableSignatureScheme: SignatureScheme {
    fn batch_verify<R: Rng>(
        &self,
        rng: &mut R,
        public_keys: &[&Self::PublicKey],
        messages: &[&[u8]],
        signatures: &[&Self::Signature],
    ) -> Result<(), SignatureError>;
}
