use crate::generic::{DdhFeCiphertext, DdhFePublicKey, DdhFeSecretKey};
use rand::CryptoRng;
use std::marker::Copy;

/*
    N : size of the vectors to compute the inner product on
    U : cyclic group element
    V : scalar from a finite field
    S : type of the inner product value
    T : type of input vector element
*/

pub trait FEInstance<const N: usize, U, V> {
    /// Return a fresh instance of the FE scheme
    fn setup() -> Self;
    /// Return a fresh public key for the FE scheme
    fn public_key<T: Copy>(&self) -> DdhFePublicKey<N, U>
    where
        V: From<T>;
    /// Return a secret key associated to the input vector
    fn secret_key<T: Copy>(&self, vector: [T; N]) -> DdhFeSecretKey<N, V, U>
    where
        V: From<T>;
}

pub trait FEPubKey<const N: usize, T, U> {
    /// Encrypt the given vector
    fn encrypt<R: CryptoRng + ?Sized>(&self, rng: &mut R, vector: [T; N]) -> DdhFeCiphertext<N, U>;
}

pub trait FEPrivKey<const N: usize, U, S> {
    /// Decrypt the given ciphertext (i.e compute an inner product) using the secret key
    fn decrypt(&self, ct: DdhFeCiphertext<N, U>, bound: S) -> Option<S>;
}
