#![warn(missing_docs, rust_2018_idioms)]

//! Module containing the implementation of the comparison
//! functions used for any implemented fuzzy hash.
//!
//! Here is a basic example of how it's working :
//!
//! ```rust
//! use std::array;
//! use fe::traits::{FEInstance, FEPubKey, FESecretKey};
//! use fe::{Instance};
//! use fuzzy_hashes::FHVector;
//! use comparator::Comparator;
//! use rand::{
//!     SeedableRng,
//!     rngs::{StdRng, SysRng},
//! };
//!
//! // The vectors you want to compare (let say vectors derived from Nilsimsa)
//! let h1: [u8; 256] = array::from_fn(|i| (i % 2) as u8);
//! let h2: [u8; 256] = array::from_fn(|i| 1 - (i % 2) as u8);
//!
//! // Concat each vector and its opposite
//! let v1: [u8; 512] = array::from_fn(|i| {
//!    if i < 256 {
//!        h1[i]
//!    } else {
//!        1 - h1[i%256]
//!    }
//! });
//! let v2: [u8; 512] = array::from_fn(|i| {
//!    if i < 256 {
//!        h2[i]
//!    } else {
//!        1 - h2[i%256]
//!    }
//! });
//!
//! // Used for encryption
//! let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
//!
//! let instance = Instance::<512>::setup();
//! // We want to encrypt vectors of u8
//! let pk = instance.public_key::<u8>();
//!
//! // Get a secret key for v1
//! let sk = instance.secret_key(v1);
//! // Encrypt v2
//! let encrypted = pk.encrypt(&mut rng, v2);
//! let score = sk.compare(encrypted);
//! ```
use fe::traits::FESecretKey;
use fe::{CipherText, SecretKey};
use fuzzy_hashes::NILSIMSA_VECTOR_SIZE_BITS;

mod traits;
pub use traits::Comparator;

/// Type alias for a FE ciphertext that contains an encrypted nilsimsa vector.
type NilsimsaCipherText = CipherText<NILSIMSA_VECTOR_SIZE_BITS>;
/// Type alias for a FE secret key that can process a nilsimsa vector.
type NilsimsaSecretKey = SecretKey<NILSIMSA_VECTOR_SIZE_BITS>;

impl Comparator<NILSIMSA_VECTOR_SIZE_BITS, i16, NilsimsaCipherText> for NilsimsaSecretKey {
    fn compare(&self, encrypted_vector: NilsimsaCipherText) -> i16 {
        let dec = self.decrypt(encrypted_vector, NILSIMSA_VECTOR_SIZE_BITS as u16);

        match dec {
            None => panic!("Something went wrong, unable to retrieve the hamming distance"),
            Some(d) => {
                128 - (((NILSIMSA_VECTOR_SIZE_BITS >> 1 )as i16) - (d as i16))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fe::Instance;
    use fe::traits::{FEInstance, FEPubKey};
    use proptest::prelude::*;
    use proptest::test_runner::{TestError, TestRunner};
    use rand::SeedableRng;
    use rand::rngs::{StdRng, SysRng};
    use std::array;
    use traits::*;

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
                let expected_score = 128
                    - secret_vec
                        .iter()
                        .zip(secret_client_vec)
                        .map(|(b1, b2)| (*b1 as i16) * (b2 as i16))
                        .sum::<i16>();

                // Construct ciphertexts : concat hash and not(hash) for both hashes
                let secret_vec_to_compare: [u8; NILSIMSA_VECTOR_SIZE_BITS] = array::from_fn(|i| {
                    if i < N {
                        secret_vec[i]
                    } else {
                        1 - secret_vec[i % N]
                    }
                });

                let client_vec_to_compare: [u8; NILSIMSA_VECTOR_SIZE_BITS] = array::from_fn(|i| {
                    if i < N {
                        secret_client_vec[i]
                    } else {
                        1 - secret_client_vec[i % N]
                    }
                });

                // Generate a fresh instance, pk and sk
                let instance = Instance::setup();
                let pk = instance.public_key::<u8>();
                let sk: NilsimsaSecretKey = instance.secret_key::<u8>(secret_vec_to_compare);

                // Encrypt the client vector
                let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
                let ct: NilsimsaCipherText = pk.encrypt(&mut rng, client_vec_to_compare);

                // Get the score
                let score = sk.compare(ct);

                assert_eq!(score, expected_score);
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
