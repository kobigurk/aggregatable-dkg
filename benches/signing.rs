use algebra::Bls12_381;
use algebraic_signature::signature::algebraic::{keypair::Keypair, srs::SRS};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;

pub fn criterion_benchmark(c: &mut Criterion) {
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

    c.bench_function("signature key proving", |b| {
        b.iter(|| keypair.prove_key().unwrap())
    });

    c.bench_function("signature key verification", |b| {
        b.iter(|| {
            proven_public_key.verify().unwrap();
        })
    });

    let mut rng = thread_rng();
    c.bench_function("signature probabilistic key verification", |b| {
        b.iter(|| {
            proven_public_key
                .verify_probabilistically(&mut rng)
                .unwrap();
        })
    });

    c.bench_function("signature signing", |b| {
        b.iter(|| {
            keypair.sign(&message[..]).unwrap();
        })
    });

    c.bench_function("signature verification", |b| {
        b.iter(|| {
            signature
                .verify(proven_public_key.clone(), &message[..])
                .unwrap();
        })
    });

    c.bench_function("signature verification and derivation", |b| {
        b.iter(|| {
            signature
                .verify_and_derive(proven_public_key.clone(), &message[..])
                .unwrap();
        })
    });

    let mut rng = thread_rng();
    c.bench_function("signature probabilistic all verification", |b| {
        b.iter(|| {
            signature
                .verify_all_probabilistically(&mut rng, proven_public_key.clone(), &message[..])
                .unwrap();
        })
    });

    c.bench_function(
        "signature probabilistic all verification and derivation",
        |b| {
            b.iter(|| {
                signature
                    .verify_all_probabilistically(&mut rng, proven_public_key.clone(), &message[..])
                    .unwrap();

                signature
                    .derive(proven_public_key.clone(), &message[..])
                    .unwrap();
            })
        },
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
