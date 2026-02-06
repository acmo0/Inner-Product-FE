#![feature(generic_const_exprs)]

use criterion::{Criterion, criterion_group, criterion_main};
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::rngs::SysRng;
use fe::Instance;
use fe::traits::{FEInstance, FEPrivKey, FEPubKey};
use std::hint::black_box;
use std::array;

const N: usize = 256;

fn not_concat<const N: usize>(v: [u8; N]) -> [u8; N + N] where [(); N + N]:, {
    array::from_fn(|i| {
        if i < N {
            v[i]
        } else {
            1 - v[i % N]
        }
    })
}

fn bench_fe(c: &mut Criterion) {
    

    let mut vector = [0u8; N];
    let mut rand_bit_vector = [0u8; N];
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    rng.fill(&mut vector);
    // Bit vector
    for (i, e) in vector.iter().enumerate() {
        rand_bit_vector[i] = e % 2;
    }

    let h1_not_concat = not_concat(rand_bit_vector);

    rng.fill(&mut vector);
    // Bit vector
    for (i, e) in vector.iter().enumerate() {
        rand_bit_vector[i] = e % 2;
    }

    println!("{:?}", rand_bit_vector);
    let h2_not_concat = not_concat(rand_bit_vector);

    let instance = Instance::setup();
    let pk = instance.public_key::<u8>();
    //let sk = instance.secret_key::<u8>(h1_not_concat);

    let ct = pk.encrypt(&mut rng, h2_not_concat);

    let mut group = c.benchmark_group("Ristretto based FH comparator");
    group.bench_function("Compare one to many", |b| {
        b.iter(|| {
            let sk = instance.secret_key::<u8>(black_box(h1_not_concat));
            let dec = sk.decrypt(black_box(ct.clone()), (16 * N) as u16);
                match dec {
                None => panic!("Something went wrong, unable to retrieve the hamming distance"),
                Some(d) => {
                    //println!("{:?}", d);
                    black_box(128 - ((N as i16) - (d as i16)));
                },
            }
        })
    });

}

criterion_group!(benches, bench_fe);
criterion_main!(benches);
