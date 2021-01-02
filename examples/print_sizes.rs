use algebra::{
    bls12_381::{Fr, G1Affine, G2Affine, G2Projective},
    AffineCurve, Bls12_381, CanonicalSerialize, PrimeField, ProjectiveCurve, UniformRand, Zero,
};
use algebraic_signature::{
    dkg::{
        config::Config,
        dealer::Dealer,
        errors::DKGError,
        participant::{Participant, ParticipantState},
        pvss::PVSSShare,
        share::{message_from_c_i, DKGTranscript, DKGTranscriptParticipant},
        srs::SRS as DKGSRS,
    },
    signature::{
        algebraic::{keypair::Keypair, srs::SRS},
        bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
        scheme::{BatchVerifiableSignatureScheme, SignatureScheme},
        schnorr::{srs::SRS as SchnorrSRS, SchnorrSignature},
    },
};
use ff_fft::{EvaluationDomain, Radix2EvaluationDomain};
use rand::thread_rng;
use std::marker::PhantomData;

fn print_algebraic_signature_sizes() {
    let rng = &mut thread_rng();
    let srs = SRS::<Bls12_381>::setup(rng).unwrap();
    let keypair = Keypair::generate_keypair(rng, srs).unwrap();
    let message = b"hello";

    let proven_public_key = keypair.prove_key().unwrap();
    proven_public_key.verify().unwrap();

    let signature = keypair.sign(&message[..]).unwrap();
    signature
        .verify_and_derive(proven_public_key.clone(), &message[..])
        .unwrap();

    let mut public_key_bytes = vec![];
    keypair.public.pk.serialize(&mut public_key_bytes).unwrap();
    println!("Algebraic public key size: {}", public_key_bytes.len());

    let mut key_proof_bytes = vec![];
    proven_public_key
        .key_proof
        .serialize(&mut key_proof_bytes)
        .unwrap();
    println!("Algebraic key proof size: {}", key_proof_bytes.len());

    let mut signature_bytes = vec![];
    signature
        .signature_proof
        .serialize(&mut signature_bytes)
        .unwrap();
    println!("Algebraic signature size: {}", signature_bytes.len());
}

fn print_bls_signature_sizes() {
    let rng = &mut thread_rng();
    let srs = BLSSRS::<BLSSignatureG1<Bls12_381>>::setup(rng).unwrap();
    let bls = BLSSignature { srs: srs.clone() };
    let keypair = bls.generate_keypair(rng).unwrap();
    let message = b"hello";
    let signature = bls.sign(rng, &keypair.0, &message[..]).unwrap();

    let mut public_key_bytes = vec![];
    keypair.1.serialize(&mut public_key_bytes).unwrap();
    println!("BLS public key size: {}", public_key_bytes.len());

    let mut signature_bytes = vec![];
    signature.serialize(&mut signature_bytes).unwrap();
    println!("BLS signature size: {}", signature_bytes.len());
}

fn print_transcript_size<
    SPOK: BatchVerifiableSignatureScheme<PublicKey = G1Affine, Secret = Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = G2Affine, Secret = Fr>,
>(
    num_nodes: usize,
    tag: &str,
    srs: DKGSRS<Bls12_381>,
    spok: SPOK,
    ssig: SSIG,
) {
    let degree = (2 * num_nodes + 2) / 3;
    let rng = &mut thread_rng();

    let u_1 = G2Projective::rand(rng).into_affine();
    let dkg_config = Config {
        srs: srs.clone(),
        u_1,
        degree,
    };

    let mut dealers = vec![];
    for i in 0..num_nodes {
        let dealer_keypair_sig = ssig.generate_keypair(rng).unwrap();
        let participant = Participant {
            pairing_type: PhantomData,
            id: i,
            public_key_sig: dealer_keypair_sig.1,
            state: ParticipantState::Dealer,
        };
        let dealer = Dealer::<Bls12_381, SSIG> {
            private_key_sig: dealer_keypair_sig.0,
            accumulated_secret: G2Projective::zero().into_affine(),
            participant,
        };

        dealers.push(dealer);
    }

    let participants = dealers
        .iter()
        .map(|d| d.participant.clone())
        .collect::<Vec<_>>();
    let num_participants = participants.len();

    let mut transcript = DKGTranscript::<Bls12_381, SPOK, SSIG>::empty(degree, num_participants);
    let mut accumulated_r = Fr::zero();
    for i in 0..num_participants {
        let r = Fr::rand(rng);
        let c = dkg_config.srs.g_g1.mul(r.into_repr()).into_affine();

        let pok_keypair = spok.from_sk(&r).unwrap();
        let pok = spok
            .sign(
                rng,
                &pok_keypair.0,
                &message_from_c_i::<Bls12_381>(c.clone()).unwrap(),
            )
            .unwrap();

        let signature_keypair = ssig.from_sk(&(dealers[i].private_key_sig)).unwrap();
        let signature = ssig
            .sign(
                rng,
                &signature_keypair.0,
                &message_from_c_i::<Bls12_381>(c.clone()).unwrap(),
            )
            .unwrap();

        let transcript_participant = DKGTranscriptParticipant::<Bls12_381, SPOK, SSIG> {
            c_i: c.clone(),
            weight: 1,
            c_i_pok: pok,
            signature_on_c_i: signature,
        };
        accumulated_r += &r;

        transcript.contributions.insert(i, transcript_participant);
    }

    let mut f = (0..=dkg_config.degree)
        .map(|_| Fr::rand(rng))
        .collect::<Vec<_>>();
    f[0] = accumulated_r;
    let domain = Radix2EvaluationDomain::<Fr>::new(participants.len())
        .ok_or(DKGError::<Bls12_381>::EvaluationDomainError)
        .unwrap();
    let y_eval_i = domain.fft(&mut f);
    let f_i = f[1..=dkg_config.degree]
        .iter()
        .map(|a| dkg_config.srs.g_g1.mul(a.into_repr()).into_affine())
        .collect::<Vec<_>>();
    let u_i_2 = dkg_config.u_1.mul(accumulated_r.into_repr()).into_affine();
    let a_i = y_eval_i
        .iter()
        .map(|a| dkg_config.srs.g_g1.mul(a.into_repr()).into_affine())
        .collect::<Vec<_>>();
    let y_i = y_eval_i
        .iter()
        .enumerate()
        .map::<Result<G2Affine, DKGError<Bls12_381>>, _>(|(i, a)| {
            Ok(participants[i]
                .public_key_sig
                .mul(a.into_repr())
                .into_affine())
        })
        .collect::<Result<_, _>>()
        .unwrap();

    transcript.pvss_share = PVSSShare::<Bls12_381> {
        f_i,
        a_i,
        y_i,
        u_i_2,
    };

    let mut transcript_bytes = vec![];
    transcript.serialize(&mut transcript_bytes).unwrap();
    println!(
        "Transcript size for participants={}, scheme={}: {}",
        num_nodes,
        tag,
        transcript_bytes.len()
    );
}

fn main() {
    print_algebraic_signature_sizes();
    print_bls_signature_sizes();

    let rng = &mut thread_rng();
    let srs = DKGSRS::<Bls12_381>::setup(rng).unwrap();

    let bls_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
        srs: BLSSRS {
            g_public_key: srs.h_g2,
            g_signature: srs.g_g1,
        },
    };
    let bls_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> {
        srs: BLSSRS {
            g_public_key: srs.g_g1,
            g_signature: srs.h_g2,
        },
    };
    print_transcript_size(64, "bls", srs.clone(), bls_pok.clone(), bls_sig.clone());
    print_transcript_size(128, "bls ", srs.clone(), bls_pok.clone(), bls_sig.clone());
    print_transcript_size(256, "bls ", srs.clone(), bls_pok.clone(), bls_sig.clone());
    print_transcript_size(8192, "bls ", srs.clone(), bls_pok.clone(), bls_sig.clone());

    let schnorr_sig = SchnorrSignature::<G2Affine> {
        srs: SchnorrSRS {
            g_public_key: srs.h_g2,
        },
    };
    let schnorr_pok = SchnorrSignature::<G1Affine> {
        srs: SchnorrSRS {
            g_public_key: srs.g_g1,
        },
    };
    print_transcript_size(
        64,
        "schnorr",
        srs.clone(),
        schnorr_pok.clone(),
        schnorr_sig.clone(),
    );
    print_transcript_size(
        128,
        "schnorr",
        srs.clone(),
        schnorr_pok.clone(),
        schnorr_sig.clone(),
    );
    print_transcript_size(
        256,
        "schnorr",
        srs.clone(),
        schnorr_pok.clone(),
        schnorr_sig.clone(),
    );
    print_transcript_size(
        8192,
        "schnorr",
        srs.clone(),
        schnorr_pok.clone(),
        schnorr_sig.clone(),
    );
}
