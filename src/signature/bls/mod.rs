use crate::signature::{
    scheme::{AggregatableSignatureScheme, BatchVerifiableSignatureScheme, SignatureScheme},
    utils::{errors::SignatureError, hash::hash_to_group},
};
use algebra::{
    AffineCurve, Field, One, PairingEngine, PrimeField, ProjectiveCurve, UniformRand, Zero,
};
use rand::Rng;
use srs::SRS;
use std::{fmt::Debug, ops::Neg};

pub mod srs;

const PERSONALIZATION: &[u8] = b"BLSSIGNA";

pub trait BLSSignatureScheme: Debug + Clone + PartialEq {
    type PublicKeyGroup: AffineCurve;
    type SignatureGroup: AffineCurve<
            ScalarField = <Self::PublicKeyGroup as AffineCurve>::ScalarField,
            Projective = Self::SignatureGroupProjective,
        > + From<Self::SignatureGroupProjective>;
    type SignatureGroupProjective: ProjectiveCurve<
            Affine = Self::SignatureGroup,
            ScalarField = <Self::SignatureGroup as AffineCurve>::ScalarField,
            BaseField = <Self::SignatureGroup as AffineCurve>::BaseField,
        > + From<Self::SignatureGroup>
        + Into<Self::SignatureGroup>
        + std::ops::MulAssign<<Self::PublicKeyGroup as AffineCurve>::ScalarField>;
    type TargetGroup: Field;

    fn product_of_pairings(
        pairs: Vec<(Self::PublicKeyGroup, Self::SignatureGroup)>,
    ) -> Self::TargetGroup;

    fn batch_product_of_pairings_is_one<R: Rng>(
        rng: &mut R,
        pairs: Vec<Vec<(Self::PublicKeyGroup, Self::SignatureGroup)>>,
    ) -> bool;
}

#[derive(Clone, Debug, PartialEq)]
pub struct BLSSignature<B: BLSSignatureScheme> {
    pub srs: SRS<B>,
}

impl<B: BLSSignatureScheme> SignatureScheme for BLSSignature<B> {
    type SRS = SRS<B>;
    type Secret = <B::PublicKeyGroup as AffineCurve>::ScalarField;
    type PublicKey = B::PublicKeyGroup;
    type Signature = B::SignatureGroup;

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
        _: &mut R,
        sk: &Self::Secret,
        message: &[u8],
    ) -> Result<Self::Signature, SignatureError> {
        let hashed_message = hash_to_group::<B::SignatureGroup>(PERSONALIZATION, message)?;
        let signature = hashed_message.mul(sk.into_repr());
        let sig = signature.into_affine();
        Ok(sig)
    }

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureError> {
        let hashed_message = hash_to_group::<B::SignatureGroup>(PERSONALIZATION, message)?;

        let eq = vec![
            (*public_key, hashed_message.into_affine()),
            (self.srs.g_public_key.neg(), *signature),
        ];
        let sig = B::product_of_pairings(eq);
        if !sig.is_one() {
            return Err(SignatureError::BLSVerify);
        }

        Ok(())
    }
}

impl<B: BLSSignatureScheme> AggregatableSignatureScheme for BLSSignature<B> {
    fn aggregate_public_keys(
        &self,
        public_keys: &[&Self::PublicKey],
    ) -> Result<Self::PublicKey, SignatureError> {
        Ok(public_keys
            .iter()
            .fold(Self::PublicKey::zero(), |acc, &x| acc + *x))
    }

    fn aggregate_signatures(
        &self,
        signatures: &[&Self::Signature],
    ) -> Result<Self::Signature, SignatureError> {
        Ok(signatures
            .iter()
            .fold(Self::Signature::zero(), |acc, &x| acc + *x))
    }
}

impl<B: BLSSignatureScheme> BatchVerifiableSignatureScheme for BLSSignature<B> {
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
        let mut pairs = vec![];
        for i in 0..public_keys.len() {
            let hashed_message = hash_to_group::<B::SignatureGroup>(PERSONALIZATION, messages[i])?;

            let eq = vec![
                (*public_keys[i], hashed_message.into_affine()),
                (self.srs.g_public_key.neg(), *signatures[i]),
            ];

            pairs.push(eq);
        }

        if !B::batch_product_of_pairings_is_one(rng, pairs) {
            return Err(SignatureError::BLSVerify);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BLSSignatureG1<E: PairingEngine> {
    pairing_type: std::marker::PhantomData<E>,
}
impl<E: PairingEngine> BLSSignatureScheme for BLSSignatureG1<E> {
    type PublicKeyGroup = E::G2Affine;
    type SignatureGroup = E::G1Affine;
    type SignatureGroupProjective = E::G1Projective;
    type TargetGroup = E::Fqk;

    fn product_of_pairings(
        pairs: Vec<(Self::PublicKeyGroup, Self::SignatureGroup)>,
    ) -> Self::TargetGroup {
        let pairs = pairs
            .into_iter()
            .map(|p| (p.1.into(), p.0.into()))
            .collect::<Vec<_>>();
        E::product_of_pairings(pairs.iter())
    }

    fn batch_product_of_pairings_is_one<R: Rng>(
        rng: &mut R,
        pairs_list: Vec<Vec<(Self::PublicKeyGroup, Self::SignatureGroup)>>,
    ) -> bool {
        let alpha = E::Fr::rand(rng);

        let mut current_alpha = E::Fr::one();
        let mut batch_elements = vec![];
        let mut other_elements = vec![];
        for pairs in pairs_list {
            for pair in pairs {
                batch_elements.push(pair.1.mul(current_alpha.into_repr()));
                other_elements.push(pair.0);
            }
            current_alpha *= &alpha;
        }
        let batch_elements_affine =
            E::G1Projective::batch_normalization_into_affine(&batch_elements);
        let batch_pairs = other_elements
            .into_iter()
            .zip(batch_elements_affine.into_iter())
            .collect::<Vec<_>>();

        Self::product_of_pairings(batch_pairs).is_one()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BLSSignatureG2<E: PairingEngine> {
    pairing_type: std::marker::PhantomData<E>,
}
impl<E: PairingEngine> BLSSignatureScheme for BLSSignatureG2<E> {
    type PublicKeyGroup = E::G1Affine;
    type SignatureGroup = E::G2Affine;
    type SignatureGroupProjective = E::G2Projective;
    type TargetGroup = E::Fqk;

    fn product_of_pairings(
        pairs: Vec<(Self::PublicKeyGroup, Self::SignatureGroup)>,
    ) -> Self::TargetGroup {
        let pairs = pairs
            .into_iter()
            .map(|p| (p.0.into(), p.1.into()))
            .collect::<Vec<_>>();
        E::product_of_pairings(pairs.iter())
    }

    fn batch_product_of_pairings_is_one<R: Rng>(
        rng: &mut R,
        pairs_list: Vec<Vec<(Self::PublicKeyGroup, Self::SignatureGroup)>>,
    ) -> bool {
        let alpha = E::Fr::rand(rng);

        let mut current_alpha = E::Fr::one();
        let mut batch_elements = vec![];
        let mut other_elements = vec![];
        for pairs in pairs_list {
            for pair in pairs {
                batch_elements.push(pair.0.mul(current_alpha.into_repr()));
                other_elements.push(pair.1);
            }
            current_alpha *= &alpha;
        }
        let batch_elements_affine =
            E::G1Projective::batch_normalization_into_affine(&batch_elements);
        let batch_pairs = batch_elements_affine
            .into_iter()
            .zip(other_elements.into_iter())
            .collect::<Vec<_>>();

        Self::product_of_pairings(batch_pairs).is_one()
    }
}

#[cfg(test)]
mod test {
    use algebra::Bls12_381;

    use super::{BLSSignatureG1, BLSSignatureG2, BLSSignatureScheme, SRS};
    use crate::signature::{
        scheme::{AggregatableSignatureScheme, SignatureScheme},
        utils::tests::check_serialization,
    };

    use crate::signature::{bls::BLSSignature, scheme::BatchVerifiableSignatureScheme};
    use rand::thread_rng;

    #[test]
    fn test_simple_sig_g1() {
        test_simple_sig::<BLSSignatureG1<Bls12_381>>();
    }

    #[test]
    fn test_simple_sig_g2() {
        test_simple_sig::<BLSSignatureG2<Bls12_381>>();
    }

    fn test_simple_sig<B: BLSSignatureScheme>() {
        let rng = &mut thread_rng();
        let srs = SRS::<B>::setup(rng).unwrap();
        let bls = BLSSignature { srs };
        let keypair = bls.generate_keypair(rng).unwrap();
        let message = b"hello";

        let signature = bls.sign(rng, &keypair.0, &message[..]).unwrap();
        bls.verify(&keypair.1, &message[..], &signature).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_simple_sig_wrong_pk_g1() {
        test_simple_sig_wrong_pk::<BLSSignatureG1<Bls12_381>>();
    }
    #[test]
    #[should_panic]
    fn test_simple_sig_wrong_pk_g2() {
        test_simple_sig_wrong_pk::<BLSSignatureG2<Bls12_381>>();
    }

    fn test_simple_sig_wrong_pk<B: BLSSignatureScheme>() {
        let rng = &mut thread_rng();
        let srs = SRS::<B>::setup(rng).unwrap();
        let bls = BLSSignature { srs };
        let keypair = bls.generate_keypair(rng).unwrap();
        let message = b"hello";

        let signature = bls.sign(rng, &keypair.0, &message[..]).unwrap();

        let keypair2 = bls.generate_keypair(rng).unwrap();
        bls.verify(&keypair2.1, &message[..], &signature).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_simple_sig_wrong_message_g1() {
        test_simple_sig_wrong_message::<BLSSignatureG1<Bls12_381>>();
    }
    #[test]
    #[should_panic]
    fn test_simple_sig_wrong_message_g2() {
        test_simple_sig_wrong_message::<BLSSignatureG2<Bls12_381>>();
    }

    fn test_simple_sig_wrong_message<B: BLSSignatureScheme>() {
        let rng = &mut thread_rng();
        let srs = SRS::<B>::setup(rng).unwrap();
        let bls = BLSSignature { srs };
        let keypair = bls.generate_keypair(rng).unwrap();
        let message = b"hello";

        let signature = bls.sign(rng, &keypair.0, &message[..]).unwrap();

        let wrong_message = b"goodbye";
        bls.verify(&keypair.1, &wrong_message[..], &signature)
            .unwrap();
    }

    #[test]
    fn test_aggregated_sig_g1() {
        test_aggregated_sig::<BLSSignatureG1<Bls12_381>>();
    }

    #[test]
    fn test_aggregated_sig_g2() {
        test_aggregated_sig::<BLSSignatureG2<Bls12_381>>();
    }

    fn test_aggregated_sig<B: BLSSignatureScheme>() {
        let rng = &mut thread_rng();
        let srs = SRS::<B>::setup(rng).unwrap();
        let bls = BLSSignature { srs };
        let keypair1 = bls.generate_keypair(rng).unwrap();
        let keypair2 = bls.generate_keypair(rng).unwrap();
        let message = b"hello";

        let signature1 = bls.sign(rng, &keypair1.0, &message[..]).unwrap();
        bls.verify(&keypair1.1, &message[..], &signature1).unwrap();

        let signature2 = bls.sign(rng, &keypair2.0, &message[..]).unwrap();
        bls.verify(&keypair2.1, &message[..], &signature2).unwrap();

        let aggregated_pk = bls
            .aggregate_public_keys(&[&keypair1.1, &keypair2.1])
            .unwrap();
        let aggregated_sig = bls
            .aggregate_signatures(&[&signature1, &signature2])
            .unwrap();

        bls.verify(&aggregated_pk, message, &aggregated_sig)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_aggregated_sig_wrong_pk_g1() {
        test_aggregated_sig_wrong_pk::<BLSSignatureG1<Bls12_381>>();
    }
    #[test]
    #[should_panic]
    fn test_aggregated_sig_wrong_pk_g2() {
        test_aggregated_sig_wrong_pk::<BLSSignatureG2<Bls12_381>>();
    }
    fn test_aggregated_sig_wrong_pk<B: BLSSignatureScheme>() {
        let rng = &mut thread_rng();
        let srs = SRS::<B>::setup(rng).unwrap();
        let bls = BLSSignature { srs };
        let keypair1 = bls.generate_keypair(rng).unwrap();
        let keypair2 = bls.generate_keypair(rng).unwrap();
        let message = b"hello";

        let signature1 = bls.sign(rng, &keypair1.0, &message[..]).unwrap();
        bls.verify(&keypair1.1, &message[..], &signature1).unwrap();

        let signature2 = bls.sign(rng, &keypair2.0, &message[..]).unwrap();
        bls.verify(&keypair1.1, &message[..], &signature2).unwrap();

        let aggregated_sig = bls
            .aggregate_signatures(&[&signature1, &signature2])
            .unwrap();
        bls.verify(&keypair1.1, message, &aggregated_sig).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_aggregated_sig_wrong_message_g1() {
        test_aggregated_sig_wrong_message::<BLSSignatureG1<Bls12_381>>();
    }
    #[test]
    #[should_panic]
    fn test_aggregated_sig_wrong_message_g2() {
        test_aggregated_sig_wrong_message::<BLSSignatureG2<Bls12_381>>();
    }
    fn test_aggregated_sig_wrong_message<B: BLSSignatureScheme>() {
        let rng = &mut thread_rng();
        let srs = SRS::<B>::setup(rng).unwrap();
        let bls = BLSSignature { srs };
        let keypair1 = bls.generate_keypair(rng).unwrap();
        let keypair2 = bls.generate_keypair(rng).unwrap();
        let message = b"hello";

        let signature1 = bls.sign(rng, &keypair1.0, &message[..]).unwrap();
        bls.verify(&keypair1.1, &message[..], &signature1).unwrap();

        let signature2 = bls.sign(rng, &keypair2.0, &message[..]).unwrap();
        bls.verify(&keypair2.1, &message[..], &signature2).unwrap();

        let aggregated_pk = bls
            .aggregate_public_keys(&[&keypair1.1, &keypair2.1])
            .unwrap();
        let aggregated_sig = bls
            .aggregate_signatures(&[&signature1, &signature2])
            .unwrap();

        let wrong_message = b"goodbye";
        bls.verify(&aggregated_pk, wrong_message, &aggregated_sig)
            .unwrap();
    }

    #[test]
    fn test_simple_sig_batch_g1() {
        test_simple_sig_batch::<BLSSignatureG1<Bls12_381>>();
    }

    #[test]
    fn test_simple_sig_batch_g2() {
        test_simple_sig_batch::<BLSSignatureG2<Bls12_381>>();
    }

    fn test_simple_sig_batch<B: BLSSignatureScheme>() {
        let rng = &mut thread_rng();
        let srs = SRS::<B>::setup(rng).unwrap();
        let bls = BLSSignature { srs };
        let keypair = bls.generate_keypair(rng).unwrap();
        let message = b"hello";
        let signature = bls.sign(rng, &keypair.0, &message[..]).unwrap();
        let keypair2 = bls.generate_keypair(rng).unwrap();
        let message2 = b"hello2";
        let signature2 = bls.sign(rng, &keypair2.0, &message2[..]).unwrap();
        bls.batch_verify(
            rng,
            &[&keypair.1, &keypair2.1],
            &[&message[..], &message2[..]],
            &[&signature, &signature2],
        )
        .unwrap();
    }

    #[test]
    fn test_serialization_g1() {
        test_serialization::<BLSSignatureG1<Bls12_381>>();
    }
    #[test]
    fn test_serialization_g2() {
        test_serialization::<BLSSignatureG2<Bls12_381>>();
    }
    fn test_serialization<B: BLSSignatureScheme>() {
        let rng = &mut thread_rng();
        let srs = SRS::<B>::setup(rng).unwrap();
        let bls = BLSSignature { srs: srs.clone() };
        let keypair = bls.generate_keypair(rng).unwrap();
        let message = b"hello";
        let signature = bls.sign(rng, &keypair.0, &message[..]).unwrap();

        check_serialization(srs.clone());
        check_serialization(keypair.clone());
        check_serialization(signature.clone());
    }
}
