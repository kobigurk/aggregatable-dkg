use crate::signature::{
    scheme::{BatchVerifiableSignatureScheme, SignatureScheme},
    utils::{errors::SignatureError, hash::hash_to_field},
};
use algebra::{AffineCurve, One, PrimeField, ProjectiveCurve, UniformRand, Zero};
use algebra_core::VariableBaseMSM;
use rand::Rng;
use srs::SRS;
use std::{fmt::Debug, ops::Neg};

pub mod srs;

const PERSONALIZATION: &[u8] = b"SCHSIGNA";

#[derive(Clone, Debug, PartialEq)]
pub struct SchnorrSignature<C: AffineCurve> {
    pub srs: SRS<C>,
}

impl<C: AffineCurve> SignatureScheme for SchnorrSignature<C> {
    type SRS = SRS<C>;
    type Secret = C::ScalarField;
    type PublicKey = C;
    type Signature = (C, C::ScalarField);

    fn from_srs(srs: Self::SRS) -> Result<Self, SignatureError> {
        Ok(Self { srs })
    }

    fn generate_keypair<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Secret, Self::PublicKey), SignatureError> {
        let sk = Self::Secret::rand(rng);
        Ok((sk, self.srs.g_public_key.mul(sk.into_repr()).into_affine()))
    }

    fn from_sk(
        &self,
        sk: &Self::Secret,
    ) -> Result<(Self::Secret, Self::PublicKey), SignatureError> {
        Ok((*sk, self.srs.g_public_key.mul(sk.into_repr()).into_affine()))
    }

    fn sign<R: Rng>(
        &self,
        rng: &mut R,
        sk: &Self::Secret,
        message: &[u8],
    ) -> Result<Self::Signature, SignatureError> {
        let v = C::ScalarField::rand(rng);
        let v_g = self.srs.g_public_key.mul(v.into_repr()).into_affine();
        let mut v_g_bytes = vec![];
        v_g.serialize(&mut v_g_bytes)?;
        let mut g_bytes = vec![];
        self.srs.g_public_key.serialize(&mut g_bytes)?;

        let hashed_message = hash_to_field::<C::ScalarField>(
            PERSONALIZATION,
            &[message, &v_g_bytes, &g_bytes].concat(),
        )?;
        let r = v - &(*sk * &hashed_message);
        let sig = (v_g, r);
        Ok(sig)
    }

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureError> {
        let mut v_g_bytes = vec![];
        signature.0.serialize(&mut v_g_bytes)?;
        let mut g_bytes = vec![];
        self.srs.g_public_key.serialize(&mut g_bytes)?;

        let hashed_message = hash_to_field::<C::ScalarField>(
            PERSONALIZATION,
            &[message, &v_g_bytes, &g_bytes].concat(),
        )?;

        let check = (self.srs.g_public_key.mul(signature.1.into_repr())
            + &public_key.mul(hashed_message.into_repr()))
            .into_affine();
        if check != signature.0 {
            return Err(SignatureError::SchnorrVerify);
        }

        Ok(())
    }
}

impl<C: AffineCurve> BatchVerifiableSignatureScheme for SchnorrSignature<C> {
    fn batch_verify<R: Rng>(
        &self,
        rng: &mut R,
        public_keys: &[&Self::PublicKey],
        messages: &[&[u8]],
        signatures: &[&Self::Signature],
    ) -> Result<(), SignatureError> {
        if public_keys.len() != messages.len() || public_keys.len() != signatures.len() {
            return Err(SignatureError::BatchVerification(
                public_keys.len(),
                messages.len(),
                signatures.len(),
            ));
        }

        let alpha = C::ScalarField::rand(rng);
        let mut current_alpha = C::ScalarField::one();

        let mut g_bytes = vec![];
        self.srs.g_public_key.serialize(&mut g_bytes)?;

        let mut bases = vec![];
        let mut scalars = vec![];
        for i in 0..public_keys.len() {
            let mut v_g_bytes = vec![];
            signatures[i].0.serialize(&mut v_g_bytes)?;

            let hashed_message = hash_to_field::<C::ScalarField>(
                PERSONALIZATION,
                &[messages[i], &v_g_bytes, &g_bytes].concat(),
            )?;

            bases.push(self.srs.g_public_key.into_projective());
            scalars.push((signatures[i].1 * &current_alpha).into_repr());

            bases.push(public_keys[i].into_projective());
            scalars.push((hashed_message * &current_alpha).into_repr());

            bases.push(signatures[i].0.into_projective());
            scalars.push(current_alpha.neg().into_repr());

            current_alpha *= &alpha;
        }
        let bases = C::Projective::batch_normalization_into_affine(&bases);
        let accumulated_check = VariableBaseMSM::multi_scalar_mul(&bases, &scalars);
        if !accumulated_check.is_zero() {
            return Err(SignatureError::SchnorrVerify);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use algebra::{
        bls12_381::{G1Affine, G2Affine},
        AffineCurve,
    };

    use super::{SchnorrSignature, SRS};
    use crate::signature::{
        scheme::{BatchVerifiableSignatureScheme, SignatureScheme},
        utils::tests::check_serialization,
    };

    use rand::thread_rng;

    #[test]
    fn test_simple_sig_g1() {
        test_simple_sig::<G1Affine>();
    }

    #[test]
    fn test_simple_sig_g2() {
        test_simple_sig::<G2Affine>();
    }

    fn test_simple_sig<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let schnorr = SchnorrSignature { srs };
        let keypair = schnorr.generate_keypair(rng).unwrap();
        let message = b"hello";

        let signature = schnorr.sign(rng, &keypair.0, &message[..]).unwrap();
        schnorr
            .verify(&keypair.1, &message[..], &signature)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_simple_sig_wrong_pk_g1() {
        test_simple_sig_wrong_pk::<G1Affine>();
    }
    #[test]
    #[should_panic]
    fn test_simple_sig_wrong_pk_g2() {
        test_simple_sig_wrong_pk::<G2Affine>();
    }

    fn test_simple_sig_wrong_pk<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let schnorr = SchnorrSignature { srs };
        let keypair = schnorr.generate_keypair(rng).unwrap();
        let message = b"hello";

        let signature = schnorr.sign(rng, &keypair.0, &message[..]).unwrap();

        let keypair2 = schnorr.generate_keypair(rng).unwrap();
        schnorr
            .verify(&keypair2.1, &message[..], &signature)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_simple_sig_wrong_message_g1() {
        test_simple_sig_wrong_message::<G1Affine>();
    }
    #[test]
    #[should_panic]
    fn test_simple_sig_wrong_message_g2() {
        test_simple_sig_wrong_message::<G2Affine>();
    }

    fn test_simple_sig_wrong_message<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let schnorr = SchnorrSignature { srs };
        let keypair = schnorr.generate_keypair(rng).unwrap();
        let message = b"hello";

        let signature = schnorr.sign(rng, &keypair.0, &message[..]).unwrap();

        let wrong_message = b"goodbye";
        schnorr
            .verify(&keypair.1, &wrong_message[..], &signature)
            .unwrap();
    }

    #[test]
    fn test_simple_sig_batch_g1() {
        test_simple_sig_batch::<G1Affine>();
    }

    #[test]
    fn test_simple_sig_batch_g2() {
        test_simple_sig_batch::<G2Affine>();
    }

    fn test_simple_sig_batch<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let schnorr = SchnorrSignature { srs };
        let keypair = schnorr.generate_keypair(rng).unwrap();
        let message = b"hello";
        let signature = schnorr.sign(rng, &keypair.0, &message[..]).unwrap();
        let keypair2 = schnorr.generate_keypair(rng).unwrap();
        let message2 = b"hello2";
        let signature2 = schnorr.sign(rng, &keypair2.0, &message2[..]).unwrap();
        schnorr
            .batch_verify(
                rng,
                &[&keypair.1, &keypair2.1],
                &[&message[..], &message2[..]],
                &[&signature, &signature2],
            )
            .unwrap();
    }

    #[test]
    fn test_serialization_g1() {
        test_serialization::<G1Affine>();
    }
    #[test]
    fn test_serialization_g2() {
        test_serialization::<G2Affine>();
    }
    fn test_serialization<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let schnorr = SchnorrSignature { srs: srs.clone() };
        let keypair = schnorr.generate_keypair(rng).unwrap();
        let message = b"hello";
        let signature = schnorr.sign(rng, &keypair.0, &message[..]).unwrap();

        check_serialization(srs.clone());
        check_serialization(keypair.clone());
        check_serialization(signature.clone());
    }
}
