//! Module containing traits that will be implemented for functionnal encryption.
//!
//! Here are the notation for the generic parameters :
//! * N : size of the vectors to compute the inner product on
//! * U : cyclic group element
//! * V : scalar from a finite field
//! * S : type of the inner product value
//! * T : type of input vector element

use crate::generic::{DdhFeCiphertext, DdhFePublicKey, DdhFeSecretKey};
use rand::CryptoRng;
use serde::{Serialize, de::DeserializeOwned};
use std::marker::Copy;

/// Trait for a generic functionnal encryption instance. The idea is that an instance should
/// be able to generate a public key made of group element for an arbitrary sized vector, and
/// should compute an secret key for any given input vector of that same size.
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

/// Trait for a generic public key of the functionnal encryption scheme. A public key should
/// be able to encrypt a vector of the same size of itself and return the associated ciphertext.
pub trait FEPubKey<const N: usize, T, U>: Serialize + DeserializeOwned {
    /// Encrypt the given vector
    fn encrypt<R: CryptoRng + ?Sized>(&self, rng: &mut R, vector: [T; N]) -> DdhFeCiphertext<N, U>;
}

/// Trait for a generic secret key for the functionnal encryption scheme. The idea is that it
/// should allow any structure that implements the FECipherText trait to be "decrypted", and
/// returns the scalar product between the encrypted vector and the one given in the secret key
// if its value is less than a user-supplied bound.
pub trait FESecretKey<const N: usize, U, S>: Serialize + DeserializeOwned {
    /// Decrypt the given ciphertext (i.e compute an inner product) using the secret key
    fn decrypt(&self, ct: impl FECipherText<U>, bound: S) -> Option<S>;
}

/// Trait that a ciphertext has to implement (i.e just getter for the field of the struct).
pub trait FECipherText<U>: Serialize + DeserializeOwned {
    /// Getter for the field "c" of the ciphertext struct.
    fn get_c(&self) -> U;
    /// Getter for the field "d" of the ciphertext struct.
    fn get_d(&self) -> U;
    /// Getter for the field "e" of the ciphertext struct.
    fn get_e(&self) -> &[U];
}
