use algebra::Bls12_381;
use algebraic_signature::signature::{
    bls::{srs::SRS, BLSSignature, BLSSignatureG1},
    scheme::SignatureScheme,
};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;

pub fn criterion_benchmark(c: &mut Criterion) {
    let rng = &mut thread_rng();
    let srs = SRS::<BLSSignatureG1<Bls12_381>>::setup(rng).unwrap();
    let bls = BLSSignature { srs };
    let keypair = bls.generate_keypair(rng).unwrap();
    let message = b"hello";

    let signature = bls.sign(rng, &keypair.0, &message[..]).unwrap();
    c.bench_function("bls signing", |b| {
        b.iter(|| {
            let _signature = bls.sign(rng, &keypair.0, &message[..]).unwrap();
        });
    });

    bls.verify(&keypair.1, &message[..], &signature).unwrap();

    c.bench_function("bls verification", |b| {
        b.iter(|| {
            bls.verify(&keypair.1, &message[..], &signature).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
