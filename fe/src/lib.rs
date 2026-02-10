#[cfg(all(feature = "finite-field", feature = "elliptic-curve"))]
compile_error!(
    "Can't use both `elliptic-curve` and `finite-field` features. They are mutualy exclusive."
);

#[cfg(all(not(feature = "finite-field"), not(feature = "elliptic-curve")))]
compile_error!(
    "Must enable either `elliptic-curve` or `finite-field` features (they are mutualy exclusive)."
);

cfg_if::cfg_if! {
    if #[cfg(feature = "elliptic-curve")] {
        mod ec_fe;
        pub use ec_fe::*;
    } else if #[cfg(feature = "finite-field")] {
        mod ff_fe;
        mod consts;
        pub use ff_fe::*;
    }
}

mod generic;
pub mod traits;

#[cfg(test)]
mod tests {
    use super::traits::*;
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{TestError, TestRunner};
    use rand::{
        SeedableRng,
        rngs::{StdRng, SysRng},
    };

    const N: usize = 512;

    fn fresh_instance() -> (Instance<N>, PublicKey<N>) {
        println!("[test] Generating instance...");
        let instance: Instance<N> = Instance::<N>::setup();
        let pk = instance.public_key::<u8>();

        (instance, pk)
    }

    prop_compose! {
        fn two_random_vec()(secret_vec in prop::array::uniform(0u8..))
                         (secret_client_vec in prop::array::uniform(0u8..), secret_vec in Just(secret_vec))
                         -> ([u8; N], [u8; N]) {
            (secret_vec, secret_client_vec)
        }
    }
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
        // Speed up
        let bound = (N / 2) as u16;
        let (instance, pk) = fresh_instance();

        let result = runner.run(
            &two_random_vec(),
            |(secret_vec, secret_client_vec): ([u8; N], [u8; N])| {
                let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
                let sk = instance.secret_key(secret_vec);

                let ct = pk.encrypt(&mut rng, secret_client_vec);

                let scalar_prod = sk.decrypt(ct, bound);

                let expected: u16 = secret_vec
                    .iter()
                    .zip(secret_client_vec)
                    .map(|(a, b)| (*a as u16) * (b as u16))
                    .sum();

                if expected >= bound {
                    assert_eq!(scalar_prod, None);
                } else {
                    assert_eq!(scalar_prod, Some(expected));
                }
                Ok(())
            },
        );

        match result {
            Ok(()) => (),
            Err(TestError::Fail(_, value)) => println!("Found failing case {:?}", value),
            result => panic!("Unexpected result {:?}", result),
        }
    }

    #[test]
    fn test_bit_vectors() {
        let mut runner = TestRunner::default();
        let bound = N as u16;

        let (instance, pk) = fresh_instance();

        let result = runner.run(
            &two_random_bitvec(),
            |(secret_vec, secret_client_vec): ([u8; N], [u8; N])| {
                let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
                let sk = instance.secret_key(secret_vec);

                let ct = pk.encrypt(&mut rng, secret_client_vec);

                let scalar_prod = sk.decrypt(ct, bound);

                let expected: u16 = secret_vec
                    .iter()
                    .zip(secret_client_vec)
                    .map(|(a, b)| (*a as u16) * (b as u16))
                    .sum();

                println!("Expected {:?}, found {:?}", expected, scalar_prod);
                if expected >= bound {
                    assert_eq!(scalar_prod, None);
                } else {
                    assert_eq!(scalar_prod, Some(expected));
                }
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
