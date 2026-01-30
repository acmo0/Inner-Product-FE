use criterion::{Criterion, criterion_group, criterion_main};
use num_bigint::BigUint;
use rand::Rng;
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::rngs::SysRng;
use ristretto_znz_fe::ddh_fe::DdhFeInstance;
use std::hint::black_box;

const N: usize = 512;

fn bench_ddh_fe(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ristretto FE");

    let instance = DdhFeInstance::<N>::new();
    let pk = instance.get_public_key();

    let mut vector = [0u8; N];
    let mut rand_bit_vector = [0u8; N];
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    rng.fill(&mut vector);
    // Bit vector
    for (i, e) in vector.iter().enumerate() {
        rand_bit_vector[i] = e % 2;
    }
    group.bench_function("Encrypt", |b| {
        b.iter(|| pk.encrypt(&mut rng, black_box(vector)))
    });

    let ct = pk.encrypt(&mut rng, vector);
    let sk = instance.secret_key_gen(vector);
    let bound = BigUint::from(N);

    group.bench_function("Decrypt", |b| {
        b.iter(|| sk.decrypt_bf(black_box(ct.clone()), black_box(bound.clone())))
    });
}

criterion_group!(benches, bench_ddh_fe);
criterion_main!(benches);
