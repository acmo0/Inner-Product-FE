use criterion::{Criterion, criterion_group, criterion_main};
use fe::Instance;
use fe::traits::{FEInstance, FEPrivKey, FEPubKey};
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::rngs::SysRng;
use std::hint::black_box;

const N: usize = 512;

fn bench_fe(c: &mut Criterion) {
    #[cfg(feature = "elliptic-curve")]
    let mut group = c.benchmark_group("Ristretto FE");
    #[cfg(feature = "finite-field")]
    let mut group = c.benchmark_group("DH n°15 FE");

    let instance = Instance::<N>::setup();
    let pk = instance.public_key::<u8>();

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
    let sk = instance.secret_key(vector);
    let bound = N as u16;

    group.bench_function("Decrypt", |b| {
        b.iter(|| sk.decrypt(black_box(ct.clone()), black_box(bound.clone())))
    });
}

criterion_group!(benches, bench_fe);
criterion_main!(benches);
