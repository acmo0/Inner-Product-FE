#![feature(generic_const_exprs)]

use fe::Instance;
use fuzzy_hashes::Nilsimsa;
use rand::rngs::{StdRng, SysRng};
use rand::SeedableRng;
use fe::traits::{FEInstance, FEPrivKey, FEPubKey};
use std::array;


fn not_concat<const N: usize>(v: [u8; N]) -> [u8; N + N] where [(); N + N]:, {
    array::from_fn(|i| {
        if i < N {
            v[i]
        } else {
            1 - v[i % N]
        }
    })
}

fn compare<const N: usize>(h1_bits: [u8; N], h2_bits: [u8; N]) -> i16 where [(); N + N]:, {
    let h1_not_concat = not_concat(h1_bits);
    let h2_not_concat = not_concat(h2_bits);

    let instance = Instance::setup();
    let pk = instance.public_key::<u8>();
    let sk = instance.secret_key::<u8>(h1_not_concat);
    
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();

    let ct = pk.encrypt(&mut rng, h2_not_concat);
    let dec = sk.decrypt(ct, (16 * N) as u16);

    match dec {
        None => panic!("Something went wrong, unable to retrieve the hamming distance"),
        Some(d) => {
            println!("{:?}", d);
            128 - ((N as i16) - (d as i16))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{TestError, TestRunner};

    // Size in bit of a nilsimsa hash
    const N: usize = 256;

    prop_compose! {
        fn two_random_bitvec()(secret_vec in prop::array::uniform(0u8..2u8))
                         (secret_client_vec in prop::array::uniform(0u8..2u8), secret_vec in Just(secret_vec))
                         -> ([u8; N], [u8; N]) {
            (secret_vec, secret_client_vec)
        }
    }

    #[test]
    fn test_correctness() {
        let mut runner = TestRunner::default();
        
        let result = runner.run(
            &two_random_bitvec(),
            |(secret_vec, secret_client_vec): ([u8; N], [u8; N])| {
                assert_eq!(compare::<N>(secret_vec, secret_client_vec), 128 - secret_vec.iter().zip(secret_client_vec).map(|(b1, b2)| (*b1 as i16) * (b2 as i16)).sum::<i16>());
                Ok(())
            },
        );

        match result {
            Ok(()) => (),
            Err(TestError::Fail(_, value)) => println!("Found failing case {:?}", value),
            result => panic!("Unexpected result {:?}", result),
        }
    }
}