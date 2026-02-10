use fe::traits::{FECipherText, FEInstance, FEPubKey, FESecretKey};
use fe::{CipherText, Instance, SecretKey};

pub trait Comparator<const N: usize, T, E> {
    fn compare(&self, encrypted_vector: E) -> T;
}
