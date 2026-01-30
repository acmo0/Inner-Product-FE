use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use num_znz_fe::ddh_fe::DdhFeInstance;
use rand::Rng;
use rand::RngExt;
use std::hint::black_box;

const N: usize = 512;

fn bench_ddh_fe(c: &mut Criterion) {
    let mut group = c.benchmark_group("BigUint FE");
    for size in [3072].iter() {
        let instance = DdhFeInstance::<N>::new_from_dhg15();
        let pk = instance.get_public_key();

        let mut vector = [0u8; N];
        let mut rand_bit_vector = [0u8; N];
        rand::thread_rng().fill(&mut vector);
        // Bit vector
        for (i, e) in vector.iter().enumerate() {
            rand_bit_vector[i] = e % 2;
        }
        group.bench_with_input(BenchmarkId::new("Encrypt", size), size, |b, &_size| {
            b.iter(|| pk.encrypt(black_box(vector)))
        });

        let ct = pk.encrypt(vector);
        let sk = instance.secret_key_gen(vector);

        group.bench_with_input(BenchmarkId::new("Decrypt", size), size, |b, &_size| {
            b.iter(|| sk.decrypt_bf(black_box(ct.clone()), 1024u16.into()))
        });
        // group.bench_with_input(BenchmarkId::new("Generate instance", size), size, |b, &size| b.iter(|| DdhFeInstance::<N>::new(size)));
    }
}

criterion_group!(benches, bench_ddh_fe);
criterion_main!(benches);
