use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use malachite::Natural;
use malachite::base::num::basic::traits::Zero;
use malachite_znz_fe::ddh_fe::DdhFeInstance;
use rand::Rng;
use rand::RngExt;
use std::array;
use std::hint::black_box;

const N: usize = 512;

fn bench_ddh_fe(c: &mut Criterion) {
    let mut group = c.benchmark_group("Malachite FE");

    let instance = DdhFeInstance::<N>::new_from_dhg15();
    let pk = instance.get_public_key();

    let mut vector = [0u8; N];
    let mut rand_bit_vector: [Natural; N] = array::from_fn(|_| Natural::ZERO);

    rand::thread_rng().fill(&mut vector);
    // Bit vector
    for (i, e) in vector.iter().enumerate() {
        rand_bit_vector[i] = Natural::from(e % 2);
    }

    group.bench_function("Encrypt", |b| {
        b.iter(|| pk.encrypt(black_box(rand_bit_vector.clone())))
    });

    let ct = pk.encrypt(rand_bit_vector.clone());
    let sk = instance.secret_key_gen(rand_bit_vector);

    group.bench_function("Decrypt", |b| {
        b.iter(|| sk.decrypt_bf(black_box(ct.clone()), 1024u16.into()))
    });
}

criterion_group!(benches, bench_ddh_fe);
criterion_main!(benches);
