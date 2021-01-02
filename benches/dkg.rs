use algebra::{
    bls12_381::{Bls12_381, Fr, G1Affine, G2Affine, G2Projective},
    ProjectiveCurve, UniformRand, Zero,
};
use algebraic_signature::{
    dkg::{
        aggregator::DKGAggregator,
        config::Config,
        dealer::Dealer,
        node::Node,
        participant::{Participant, ParticipantState},
        share::DKGTranscript,
        srs::SRS,
    },
    signature::{
        bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
        scheme::BatchVerifiableSignatureScheme,
        schnorr::{srs::SRS as SchnorrSRS, SchnorrSignature},
    },
};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use std::marker::PhantomData;

pub fn criterion_benchmark(c: &mut Criterion) {
    let rng = &mut thread_rng();
    let srs = SRS::<Bls12_381>::setup(rng).unwrap();

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
    for i in 0..10 {
        let num_nodes = 1 << i;
        for j in 0..i {
            let degree = 1 << j;
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

            let mut aggregator = DKGAggregator {
                config: dkg_config.clone(),
                scheme_pok: spok.clone(),
                scheme_sig: ssig.clone(),
                participants: participants.clone().into_iter().enumerate().collect(),
                transcript: DKGTranscript::empty(dkg_config.degree, num_participants),
            };

            let mut nodes = vec![];
            for i in 0..num_nodes {
                let degree = dkg_config.degree;
                let node = Node {
                    aggregator: DKGAggregator {
                        config: dkg_config.clone(),
                        scheme_pok: spok.clone(),
                        scheme_sig: ssig.clone(),
                        participants: participants.clone().into_iter().enumerate().collect(),
                        transcript: DKGTranscript::empty(degree, num_participants),
                    },
                    dealer: dealers[i].clone(),
                };
                nodes.push(node);
            }
            for i in 0..num_nodes {
                let share = nodes[i].share(rng).unwrap();
                for j in 0..num_nodes {
                    nodes[j]
                        .receive_share_and_decrypt(rng, share.clone())
                        .unwrap();
                }
                aggregator.receive_share(rng, &share.clone()).unwrap();
                if i == 0 {
                    c.bench_function(
                        &format!(
                            "dkg(sig_scheme={}, nodes={}, degree={}) share",
                            tag, num_nodes, degree
                        ),
                        |b| b.iter(|| nodes[i].share(rng).unwrap()),
                    );
                    c.bench_function(
                        &format!(
                            "dkg(sig_scheme={}, nodes={}, degree={}) aggregator receive share",
                            tag, num_nodes, degree
                        ),
                        |b| {
                            b.iter(|| {
                                let mut aggregator = DKGAggregator {
                                    config: dkg_config.clone(),
                                    scheme_pok: spok.clone(),
                                    scheme_sig: ssig.clone(),
                                    participants: participants
                                        .clone()
                                        .into_iter()
                                        .enumerate()
                                        .collect(),
                                    transcript: DKGTranscript::empty(
                                        dkg_config.degree,
                                        num_participants,
                                    ),
                                };

                                aggregator.receive_share(rng, &share.clone()).unwrap();
                            })
                        },
                    );
                }
            }

            let transcript = aggregator.transcript;
            for i in 0..num_nodes {
                let degree = dkg_config.degree;
                let mut node = Node {
                    aggregator: DKGAggregator {
                        config: dkg_config.clone(),
                        scheme_pok: spok.clone(),
                        scheme_sig: ssig.clone(),
                        participants: participants.clone().into_iter().enumerate().collect(),
                        transcript: DKGTranscript::empty(degree, num_participants),
                    },
                    dealer: dealers[i].clone(),
                };
                node.receive_transcript_and_decrypt(rng, transcript.clone())
                    .unwrap();
                assert_eq!(
                    node.dealer.accumulated_secret,
                    nodes[i].dealer.accumulated_secret
                );
                if i == 0 {
                    c.bench_function(
                        &format!(
                            "dkg(sig_scheme={}, nodes={}, degree={}) node receive transcript and decrypt",
                            tag, num_nodes, degree
                        ),
                        |b| {
                            b.iter(|| {
                                let mut node = Node {
                                    aggregator: DKGAggregator {
                                        config: dkg_config.clone(),
                                        scheme_pok: spok.clone(),
                                        scheme_sig: ssig.clone(),
                                        participants: participants
                                            .clone()
                                            .into_iter()
                                            .enumerate()
                                            .collect(),
                                        transcript: DKGTranscript::empty(degree, num_participants),
                                    },
                                    dealer: dealers[i].clone(),
                                };
                                node.receive_transcript_and_decrypt(rng, transcript.clone())
                                    .unwrap();
                                assert_eq!(
                                    node.dealer.accumulated_secret,
                                    nodes[i].dealer.accumulated_secret
                                );
                            })
                        },
                    );
                }
            }
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
