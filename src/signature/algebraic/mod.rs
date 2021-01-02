pub mod keypair;
pub mod public_key;
pub mod signature;
pub mod srs;

pub const PERSONALIZATION: &[u8] = b"ALGEBSIG";

#[cfg(test)]
mod test {
    use algebra::Bls12_381;

    use super::{keypair::Keypair, public_key::ProvenPublicKey, signature::Signature, srs::SRS};
    use crate::signature::utils::tests::check_serialization;

    use rand::thread_rng;

    #[test]
    fn test_simple_sig() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair = Keypair::generate_keypair(rng, srs).unwrap();
        let message = b"hello";

        let proven_public_key = keypair.prove_key().unwrap();
        proven_public_key.verify().unwrap();

        let signature = keypair.sign(&message[..]).unwrap();
        signature
            .verify_and_derive(proven_public_key, &message[..])
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_simple_sig_wrong_pk() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair = Keypair::generate_keypair(rng, srs.clone()).unwrap();
        let message = b"hello";

        let signature = keypair.sign(&message[..]).unwrap();

        let keypair2 = Keypair::generate_keypair(rng, srs).unwrap();
        let proven_public_key2 = keypair2.prove_key().unwrap();
        proven_public_key2.verify().unwrap();
        signature
            .verify_and_derive(proven_public_key2, &message[..])
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_simple_sig_wrong_message() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair = Keypair::generate_keypair(rng, srs).unwrap();
        let message = b"hello";

        let proven_public_key = keypair.prove_key().unwrap();
        proven_public_key.verify().unwrap();

        let signature = keypair.sign(&message[..]).unwrap();

        let wrong_message = b"goodbye";
        signature
            .verify_and_derive(proven_public_key, &wrong_message[..])
            .unwrap();
    }

    #[test]
    fn test_aggregated_sig() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair1 = Keypair::generate_keypair(rng, srs.clone()).unwrap();
        let keypair2 = Keypair::generate_keypair(rng, srs.clone()).unwrap();
        let message = b"hello";

        let proven_public_key1 = keypair1.prove_key().unwrap();
        proven_public_key1.verify().unwrap();

        let proven_public_key2 = keypair2.prove_key().unwrap();
        proven_public_key2.verify().unwrap();

        let signature1 = keypair1.sign(&message[..]).unwrap();
        signature1
            .verify_and_derive(proven_public_key1.clone(), &message[..])
            .unwrap();

        let signature2 = keypair2.sign(&message[..]).unwrap();
        signature2
            .verify_and_derive(proven_public_key2.clone(), &message[..])
            .unwrap();

        let aggregated_pk =
            ProvenPublicKey::aggregate(&[proven_public_key1, proven_public_key2], srs.clone())
                .unwrap();
        let aggregated_sig = Signature::aggregate(&[signature1, signature2]).unwrap();

        aggregated_sig
            .verify_and_derive(aggregated_pk, message)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_aggregated_sig_wrong_pk() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair1 = Keypair::generate_keypair(rng, srs.clone()).unwrap();
        let keypair2 = Keypair::generate_keypair(rng, srs.clone()).unwrap();
        let message = b"hello";

        let proven_public_key1 = keypair1.prove_key().unwrap();
        proven_public_key1.verify().unwrap();

        let proven_public_key2 = keypair2.prove_key().unwrap();
        proven_public_key2.verify().unwrap();

        let signature1 = keypair1.sign(&message[..]).unwrap();
        signature1
            .verify_and_derive(proven_public_key1.clone(), &message[..])
            .unwrap();

        let signature2 = keypair2.sign(&message[..]).unwrap();
        signature2
            .verify_and_derive(proven_public_key2.clone(), &message[..])
            .unwrap();

        let aggregated_sig = Signature::aggregate(&[signature1, signature2]).unwrap();
        aggregated_sig
            .verify_and_derive(proven_public_key1, message)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_aggregated_sig_wrong_message() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair1 = Keypair::generate_keypair(rng, srs.clone()).unwrap();
        let keypair2 = Keypair::generate_keypair(rng, srs.clone()).unwrap();
        let message = b"hello";

        let proven_public_key1 = keypair1.prove_key().unwrap();
        proven_public_key1.verify().unwrap();

        let proven_public_key2 = keypair2.prove_key().unwrap();
        proven_public_key2.verify().unwrap();

        let signature1 = keypair1.sign(&message[..]).unwrap();
        signature1
            .verify_and_derive(proven_public_key1.clone(), &message[..])
            .unwrap();

        let signature2 = keypair2.sign(&message[..]).unwrap();
        signature2
            .verify_and_derive(proven_public_key2.clone(), &message[..])
            .unwrap();

        let aggregated_pk =
            ProvenPublicKey::aggregate(&[proven_public_key1, proven_public_key2], srs.clone())
                .unwrap();
        let aggregated_sig = Signature::aggregate(&[signature1, signature2]).unwrap();

        let wrong_message = b"goodbye";
        aggregated_sig
            .verify_and_derive(aggregated_pk, wrong_message)
            .unwrap();
    }

    #[test]
    fn test_refresh_randomness() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair = Keypair::generate_keypair(rng, srs).unwrap();
        let message = b"hello";

        let proven_public_key = keypair.prove_key().unwrap();
        proven_public_key.verify().unwrap();

        let signature = keypair.sign(&message[..]).unwrap();
        signature
            .verify_and_derive(proven_public_key, &message[..])
            .unwrap();

        let refreshed_keypair = keypair.refresh_randomness(rng).unwrap();
        let proven_refreshed_public_key = refreshed_keypair.prove_key().unwrap();
        proven_refreshed_public_key.verify().unwrap();
        signature
            .verify_and_derive(proven_refreshed_public_key.clone(), &message[..])
            .unwrap_err();

        let signature = refreshed_keypair.sign(&message[..]).unwrap();
        signature
            .verify_and_derive(proven_refreshed_public_key, &message[..])
            .unwrap();
    }

    #[test]
    fn test_simple_sig_probabilistic() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair = Keypair::generate_keypair(rng, srs).unwrap();
        let message = b"hello";

        let proven_public_key = keypair.prove_key().unwrap();
        proven_public_key.verify().unwrap();

        let signature = keypair.sign(&message[..]).unwrap();
        proven_public_key.verify_probabilistically(rng).unwrap();
        signature
            .verify_and_derive(proven_public_key, &message[..])
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_simple_sig_probabilistic_wrong_pk() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair = Keypair::generate_keypair(rng, srs.clone()).unwrap();
        let message = b"hello";

        let signature = keypair.sign(&message[..]).unwrap();

        let keypair2 = Keypair::generate_keypair(rng, srs).unwrap();
        let proven_public_key2 = keypair2.prove_key().unwrap();
        proven_public_key2.verify_probabilistically(rng).unwrap();
        proven_public_key2.verify().unwrap();
        signature
            .verify_and_derive(proven_public_key2, &message[..])
            .unwrap();
    }

    #[test]
    fn test_simple_sig_all_probabilistic() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair = Keypair::generate_keypair(rng, srs).unwrap();
        let message = b"hello";

        let proven_public_key = keypair.prove_key().unwrap();
        proven_public_key.verify().unwrap();

        let signature = keypair.sign(&message[..]).unwrap();
        signature
            .verify_all_probabilistically(rng, proven_public_key.clone(), &message[..])
            .unwrap();
        signature.derive(proven_public_key, &message[..]).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_simple_sig_all_probabilistic_wrong_pk() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair = Keypair::generate_keypair(rng, srs.clone()).unwrap();
        let message = b"hello";

        let signature = keypair.sign(&message[..]).unwrap();

        let keypair2 = Keypair::generate_keypair(rng, srs).unwrap();
        let proven_public_key2 = keypair2.prove_key().unwrap();
        proven_public_key2.verify().unwrap();
        signature
            .verify_all_probabilistically(rng, proven_public_key2.clone(), &message[..])
            .unwrap();
        signature
            .verify_and_derive(proven_public_key2, &message[..])
            .unwrap();
    }

    #[test]
    fn test_serialization() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let keypair = Keypair::generate_keypair(rng, srs.clone()).unwrap();
        let message = b"hello";
        let signature = keypair.sign(&message[..]).unwrap();

        check_serialization(srs.clone());
        check_serialization(keypair.clone());
        check_serialization(signature.clone());
    }
}
