use fe::{Instance, CipherText, SecretKey};
use fe::traits::{FEInstance, FESecretKey, FEPubKey, FECipherText};

pub trait Comparator<const N: usize, T, E> {
	fn compare(&self, encrypted_vector: E) -> T;
}