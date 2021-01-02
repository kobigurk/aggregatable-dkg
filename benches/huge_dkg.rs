use algebra::{
    bls12_381::{Bls12_381, Fr, G1Affine, G2Affine, G2Projective},
    AffineCurve, PrimeField, ProjectiveCurve, UniformRand, Zero,
};
use algebraic_signature::{
    dkg::{
        aggregator::DKGAggregator,
        config::Config,
        dealer::Dealer,
        errors::DKGError,
        node::Node,
        participant::{Participant, ParticipantState},
        pvss::PVSSShare,
        share::{message_from_c_i, DKGTranscript, DKGTranscriptParticipant},
        srs::SRS,
    },
    signature::{
        bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
        scheme::BatchVerifiableSignatureScheme,
        schnorr::{srs::SRS as SchnorrSRS, SchnorrSignature},
    },
};
use criterion::{criterion_group, criterion_main, Criterion};
use ff_fft::{EvaluationDomain, Radix2EvaluationDomain};
use rand::thread_rng;
use std::marker::PhantomData;

pub fn criterion_benchmark(c: &mut Criterion) {
    let rng = &mut thread_rng();
    let srs = SRS::<Bls12_381>::setup(rng).unwrap();

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
    benchmark_with_signature_scheme(c, "bls", srs.clone(), bls_pok.clone(), bls_sig.clone());

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
    benchmark_with_signature_scheme(
        c,
        "schnorr",
        srs.clone(),
        schnorr_pok.clone(),
        schnorr_sig.clone(),
    );
}

fn benchmark_with_signature_scheme<
    SPOK: BatchVerifiableSignatureScheme<PublicKey = G1Affine, Secret = Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = G2Affine, Secret = Fr>,
>(
    c: &mut Criterion,
    tag: &str,
    srs: SRS<Bls12_381>,
    spok: SPOK,
    ssig: SSIG,
) {
    let num_nodes = 8192;
    let degree = (2 * num_nodes + 2) / 3;
    for j in (0..=13).rev() {
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
            let dealer = Dealer {
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

        c.bench_function(
            &format!(
                "huge-dkg(j={}, sig_scheme={}, nodes={}, degree={}) share",
                j, tag, num_nodes, degree
            ),
            |b| {
                b.iter(|| {
                    let mut node = Node {
                        aggregator: DKGAggregator {
                            config: dkg_config.clone(),
                            scheme_pok: spok.clone(),
                            scheme_sig: ssig.clone(),
                            participants: participants.clone().into_iter().enumerate().collect(),
                            transcript: DKGTranscript::empty(degree, num_participants),
                        },
                        dealer: dealers[0].clone(),
                    };
                    node.share(rng).unwrap()
                })
            },
        );

        c.bench_function(
            &format!(
                "huge-dkg(j={}, sig_scheme={}, nodes={}, degree={}) aggregator receive share",
                j, tag, num_nodes, degree
            ),
            |b| {
                b.iter(|| {
                    let mut node = Node {
                        aggregator: DKGAggregator {
                            config: dkg_config.clone(),
                            scheme_pok: spok.clone(),
                            scheme_sig: ssig.clone(),
                            participants: participants.clone().into_iter().enumerate().collect(),
                            transcript: DKGTranscript::empty(degree, num_participants),
                        },
                        dealer: dealers[0].clone(),
                    };
                    let share = node.share(rng).unwrap();
                    let mut aggregator = DKGAggregator {
                        config: dkg_config.clone(),
                        scheme_pok: spok.clone(),
                        scheme_sig: ssig.clone(),
                        participants: participants.clone().into_iter().enumerate().collect(),
                        transcript: DKGTranscript::empty(dkg_config.degree, num_participants),
                    };

                    aggregator.receive_share(rng, &share.clone()).unwrap();
                })
            },
        );

        let mut transcript =
            DKGTranscript::<Bls12_381, SPOK, SSIG>::empty(degree, num_participants);
        let mut accumulated_r = Fr::zero();
        for i in 0..(1 << j) {
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

        c.bench_function(
            &format!(
                "huge-dkg(j={}, sig_scheme={}, nodes={}, degree={}) node receive transcript and decrypt",
                j, tag, num_nodes, degree
            ),
            |b| {
                b.iter(|| {
                    let mut node = Node {
                        aggregator: DKGAggregator {
                            config: dkg_config.clone(),
                            scheme_pok: spok.clone(),
                            scheme_sig: ssig.clone(),
                            participants: participants.clone().into_iter().enumerate().collect(),
                            transcript: DKGTranscript::empty(degree, num_participants),
                        },
                        dealer: dealers[0].clone(),
                    };
                    node.receive_transcript_and_decrypt(rng, transcript.clone())
                        .unwrap();
                })
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
