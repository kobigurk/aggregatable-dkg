use crate::{
    dkg::{
        aggregator::DKGAggregator,
        config::Config,
        dealer::Dealer,
        errors::DKGError,
        participant::{Participant, ParticipantState},
        pvss::{PVSSShare, PVSSShareSecrets},
        share::{message_from_c_i, DKGShare, DKGTranscript},
    },
    signature::scheme::BatchVerifiableSignatureScheme,
};
use algebra::{AffineCurve, Field, PairingEngine, PrimeField, ProjectiveCurve, UniformRand};
use ff_fft::{EvaluationDomain, Radix2EvaluationDomain};
use rand::Rng;
use std::collections::BTreeMap;

pub struct Node<
    E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
> {
    pub aggregator: DKGAggregator<E, SPOK, SSIG>,
    pub dealer: Dealer<E, SSIG>,
}

impl<
        E: PairingEngine,
        SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
        SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
    > Node<E, SPOK, SSIG>
{
    pub fn new(
        config: Config<E>,
        scheme_pok: SPOK,
        scheme_sig: SSIG,
        dealer: Dealer<E, SSIG>,
        participants: BTreeMap<usize, Participant<E, SSIG>>,
    ) -> Result<Self, DKGError<E>> {
        let degree = config.degree;
        let num_participants = participants.len();
        let node = Node {
            aggregator: DKGAggregator {
                config,
                scheme_pok,
                scheme_sig,
                participants,
                transcript: DKGTranscript::empty(degree, num_participants),
            },
            dealer,
        };
        Ok(node)
    }

    pub fn share_pvss<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(PVSSShare<E>, PVSSShareSecrets<E>), DKGError<E>> {
        let mut f = (0..=self.aggregator.config.degree)
            .map(|_| E::Fr::rand(rng))
            .collect::<Vec<_>>();
        let domain = Radix2EvaluationDomain::<E::Fr>::new(self.aggregator.participants.len())
            .ok_or(DKGError::<E>::EvaluationDomainError)?;
        let y_eval_i = domain.fft(&mut f);

        let f_i = f[1..=self.aggregator.config.degree]
            .iter()
            .map(|a| {
                self.aggregator
                    .config
                    .srs
                    .g_g1
                    .mul(a.into_repr())
                    .into_affine()
            })
            .collect::<Vec<_>>();
        let u_i_2 = self
            .aggregator
            .config
            .u_1
            .mul(f[0].into_repr())
            .into_affine();
        let a_i = y_eval_i
            .iter()
            .map(|a| {
                self.aggregator
                    .config
                    .srs
                    .g_g1
                    .mul(a.into_repr())
                    .into_affine()
            })
            .collect::<Vec<_>>();
        let y_i = y_eval_i
            .iter()
            .enumerate()
            .map::<Result<E::G2Affine, DKGError<E>>, _>(|(i, a)| {
                Ok(self
                    .aggregator
                    .participants
                    .get(&i)
                    .ok_or(DKGError::<E>::InvalidParticipantId(i))?
                    .public_key_sig
                    .mul(a.into_repr())
                    .into_affine())
            })
            .collect::<Result<_, _>>()?;
        let pvss_share = PVSSShare {
            f_i,
            u_i_2,
            a_i,
            y_i,
        };

        let my_secret = self
            .aggregator
            .config
            .srs
            .h_g2
            .mul(y_eval_i[self.dealer.participant.id].into_repr())
            .into_affine();

        let pvss_share_secrets = PVSSShareSecrets {
            f_0: f[0],
            my_secret,
        };

        Ok((pvss_share, pvss_share_secrets))
    }

    pub fn share<R: Rng>(&mut self, rng: &mut R) -> Result<DKGShare<E, SPOK, SSIG>, DKGError<E>> {
        let (pvss_share, pvss_share_secrets) = self.share_pvss(rng)?;
        let c_i = self
            .aggregator
            .config
            .srs
            .g_g1
            .mul(pvss_share_secrets.f_0.into_repr())
            .into_affine();

        let pok_keypair = self
            .aggregator
            .scheme_pok
            .from_sk(&pvss_share_secrets.f_0)?;
        let pok = self
            .aggregator
            .scheme_pok
            .sign(rng, &pok_keypair.0, &message_from_c_i(c_i)?)?;

        let signature_keypair = self
            .aggregator
            .scheme_sig
            .from_sk(&(self.dealer.private_key_sig))?;
        let signature =
            self.aggregator
                .scheme_sig
                .sign(rng, &signature_keypair.0, &message_from_c_i(c_i)?)?;

        let share = DKGShare {
            participant_id: self.dealer.participant.id,
            c_i,
            pvss_share,
            c_i_pok: pok,
            signature_on_c_i: signature,
        };

        self.dealer.participant.state = ParticipantState::DealerShared;
        Ok(share)
    }

    // Assumes that the participant id has been authenticated.
    pub fn receive_share_and_decrypt<R: Rng>(
        &mut self,
        rng: &mut R,
        share: DKGShare<E, SPOK, SSIG>,
    ) -> Result<(), DKGError<E>> {
        let participant_id = share.participant_id;

        match (|| -> Result<E::G2Affine, DKGError<E>> {
            self.aggregator.receive_share(rng, &share)?;

            let secret = share.pvss_share.y_i[self.dealer.participant.id]
                .mul(self.dealer.private_key_sig.inverse().unwrap().into_repr())
                .into_affine();

            Ok(secret)
        })() {
            Ok(secret) => {
                self.dealer.accumulated_secret = self.dealer.accumulated_secret + secret;
                let participant = self
                    .aggregator
                    .participants
                    .get_mut(&participant_id)
                    .ok_or(DKGError::<E>::InvalidParticipantId(participant_id))?;
                participant.state = ParticipantState::Verified;
            }
            Err(_) => {}
        };

        Ok(())
    }

    // Assumes that the participant id has been authenticated.
    pub fn receive_transcript_and_decrypt<R: Rng>(
        &mut self,
        rng: &mut R,
        transcript: DKGTranscript<E, SPOK, SSIG>,
    ) -> Result<(), DKGError<E>> {
        self.aggregator.receive_transcript(rng, &transcript)?;

        let secret = transcript.pvss_share.y_i[self.dealer.participant.id]
            .mul(self.dealer.private_key_sig.inverse().unwrap().into_repr())
            .into_affine();

        for (participant_id, _) in transcript.contributions {
            let participant = self
                .aggregator
                .participants
                .get_mut(&participant_id)
                .ok_or(DKGError::<E>::InvalidParticipantId(participant_id))?;
            participant.state = ParticipantState::Verified;
        }
        self.dealer.accumulated_secret = self.dealer.accumulated_secret + secret;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
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
            scheme::{BatchVerifiableSignatureScheme, SignatureScheme},
            schnorr::{srs::SRS as SchnorrSRS, SchnorrSignature},
        },
    };
    use algebra::{
        bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
        ProjectiveCurve, UniformRand, Zero,
    };
    use rand::thread_rng;
    use std::marker::PhantomData;

    #[test]
    fn test_one() {
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
        let dealer_keypair_sig = bls_sig.generate_keypair(rng).unwrap();
        let dealer = Dealer {
            private_key_sig: dealer_keypair_sig.0,
            accumulated_secret: G2Projective::zero().into_affine(),
            participant: Participant {
                pairing_type: PhantomData,
                id: 0,
                public_key_sig: dealer_keypair_sig.1,
                state: ParticipantState::Dealer,
            },
        };

        let u_1 = G2Projective::rand(rng).into_affine();
        let dkg_config = Config {
            srs: srs.clone(),
            u_1,
            degree: 10,
        };

        let participants = vec![dealer.participant.clone()];
        let degree = dkg_config.degree;
        let num_participants = participants.len();

        let mut node = Node {
            aggregator: DKGAggregator {
                config: dkg_config.clone(),
                scheme_pok: bls_pok.clone(),
                scheme_sig: bls_sig.clone(),
                participants: participants.clone().into_iter().enumerate().collect(),
                transcript: DKGTranscript::empty(degree, num_participants),
            },
            dealer,
        };

        node.share(rng).unwrap();
    }

    #[test]
    fn test_2_nodes_verify() {
        const NODES: usize = 4;

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

        let u_1 = G2Projective::rand(rng).into_affine();
        let dkg_config = Config {
            srs: srs.clone(),
            u_1,
            degree: 2,
        };

        let mut dealers = vec![];
        for i in 0..NODES {
            let dealer_keypair_sig = bls_sig.generate_keypair(rng).unwrap();
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
        let mut nodes = vec![];
        for i in 0..NODES {
            let degree = dkg_config.degree;
            let num_participants = participants.len();
            let node = Node {
                aggregator: DKGAggregator {
                    config: dkg_config.clone(),
                    scheme_pok: bls_pok.clone(),
                    scheme_sig: bls_sig.clone(),
                    participants: participants.clone().into_iter().enumerate().collect(),
                    transcript: DKGTranscript::empty(degree, num_participants),
                },
                dealer: dealers[i].clone(),
            };
            nodes.push(node);
        }
        for i in 0..NODES {
            let node = &mut nodes[i];
            let share = node.share(rng).unwrap();
            for j in 0..NODES {
                nodes[j]
                    .receive_share_and_decrypt(rng, share.clone())
                    .unwrap();
            }
        }
    }

    #[test]
    fn test_2_nodes_and_aggregator_bls() {
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
        test_2_nodes_and_aggregator_with_signature_scheme(srs, bls_pok, bls_sig);
    }
    #[test]
    fn test_2_nodes_and_aggregator_schnorr() {
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
        test_2_nodes_and_aggregator_with_signature_scheme(srs, schnorr_pok, schnorr_sig);
    }

    fn test_2_nodes_and_aggregator_with_signature_scheme<
        SPOK: BatchVerifiableSignatureScheme<PublicKey = G1Affine, Secret = Fr>,
        SSIG: BatchVerifiableSignatureScheme<PublicKey = G2Affine, Secret = Fr>,
    >(
        srs: SRS<Bls12_381>,
        spok: SPOK,
        ssig: SSIG,
    ) {
        const NODES: usize = 4;

        let rng = &mut thread_rng();

        let u_1 = G2Projective::rand(rng).into_affine();
        let dkg_config = Config {
            srs: srs.clone(),
            u_1,
            degree: 2,
        };

        let mut dealers = vec![];
        for i in 0..NODES {
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
        for i in 0..NODES {
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
        // Make participant 0 have weight 2.
        // Should ignore participant 1, since we modify its share to be bad.
        for i in 0..NODES {
            let node = &mut nodes[i];
            let mut share = node.share(rng).unwrap();
            for j in 0..NODES {
                if i == 1 {
                    share.c_i = G1Projective::rand(rng).into_affine();
                }

                nodes[j]
                    .receive_share_and_decrypt(rng, share.clone())
                    .unwrap();
                if i == 0 {
                    nodes[j]
                        .receive_share_and_decrypt(rng, share.clone())
                        .unwrap();
                }
            }
            if i != 1 {
                aggregator.receive_share(rng, &share.clone()).unwrap();
                if i == 0 {
                    aggregator.receive_share(rng, &share.clone()).unwrap();
                }
            } else {
                aggregator.receive_share(rng, &share.clone()).unwrap_err();
            }
        }

        let transcript = aggregator.transcript;
        for i in 0..NODES {
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
                assert_eq!(transcript.contributions[&i].weight, 2);
            } else if i == 1 {
                assert!(transcript.contributions.get(&i).is_none());
            } else {
                assert_eq!(transcript.contributions[&i].weight, 1);
            }
        }
    }
}
