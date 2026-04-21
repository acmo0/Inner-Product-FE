#![warn(missing_docs, rust_2018_idioms)]

//! Module containing all the messages/types exchanged over the
// nextwork between the Authority, the Compute Server and the Client.
use anyhow::{Error, Result};
use fe::{CipherText, CompressedPublicKey, CompressedSecretKey, PublicKey, SecretKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::array;
use std::array::TryFromSliceError;
use std::fmt::Debug;
/*
    Constants to define a Nilsisma FH size
*/
/// Length of a Nilsimsa fuzzy hash
pub const NILSIMSA_FH_SIZE_BYTES: usize = 32;
/// Length in bytes of a Nilsimsa fuzzy hash vector
/// (i.e the fuzzy hash itself, and its opposite concatenated).
pub const NILSIMSA_VECTOR_SIZE_BYTES: usize = 64;
/// Length in bytes of a Nilsimsa fuzzy hash vector
/// (i.e the fuzzy hash itself, and its opposite concatenated).
pub const NILSIMSA_VECTOR_SIZE_BITS: usize = 512;

/*
    Messages between an Authority and a Compute server
*/
/// Request send to the Authority by the Compute server to generate a fresh instance,
/// generate a public key and encrypt the provided vectors in the GenerateInstanceRequest.
pub type GenerateInstanceRequest<T> = Vec<FHVector<T>>;

/// Reply send to the Compute server by the Authority. It contains the secret keys for the
/// previously requested vectors and the associated public key.
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateInstanceResponse<const N: usize>(
    pub Vec<(PublicKey<N>, Vec<CompressedSecretKey>)>,
);

impl<const N: usize> GenerateInstanceResponse<N> {
    /// "Decompress" the response to retrieve the PublicKey and the SecretKey with
    /// the correct types for the underlying FE implementation.
    pub fn decompress(&self) -> Result<Vec<(PublicKey<N>, Vec<SecretKey<N>>)>, Error> {
        let mut vec_uncompressed = vec![];

        for instance in self.0.iter() {
            let pub_key = instance.0.clone();
            let sks = instance
                .1
                .iter()
                .map(|v| match SecretKey::<N>::try_from(v) {
                    Ok(vec) => vec,
                    Err(_) => {
                        panic!("Unable to decompress a vector from the authority, abort.");
                    }
                })
                .collect();
            vec_uncompressed.push((pub_key, sks));
        }
        Ok(vec_uncompressed)
    }
}

impl<const N: usize> From<Vec<(PublicKey<N>, Vec<SecretKey<N>>)>> for GenerateInstanceResponse<N> {
    /// Allow to easily "compress" the public key and the secret keys for network transmission.
    fn from(value: Vec<(PublicKey<N>, Vec<SecretKey<N>>)>) -> GenerateInstanceResponse<N> {
        let compressed = value
            .into_iter()
            .map(|(pk, sks)| (pk, sks.iter().map(CompressedSecretKey::from).collect()))
            .collect();
        GenerateInstanceResponse(compressed)
    }
}

/*
    Messages between a Client and a Compute server.
*/
/// Request send to the compute server by the client
/// to indicate which fuzzy hash to compare.

#[derive(Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum HashComparisonRequest {
    /// Indicate that the client wants to compare Nilsimsa fuzzy hash.
    NILSIMSA,
}

/// Request to the client to encrypt its hash using
/// the given public key in the request.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionRequest<const N: usize, T> {
    /// Field containing the public key to encrypt the fuzzy hash
    pub pk: Option<CompressedPublicKey<N>>,
    /// Potential similarity score of any computed by the server
    /// before sending that encryption request
    pub similarity_scores: Option<Vec<T>>,
}

/// Response from the client to the server which will
/// compute the partial decryption on.
#[derive(Debug, Serialize, Deserialize)]
pub enum EncryptionResponse<const N: usize> {
    /// The client send an encrypted fuzzy hash to compare.
    EncryptedVector(CipherText<N>),
    /// Indicate that the client want to stop th exchange.
    EndOfComparison,
}

/// Enum representing a fuzzy hash vector. For now, only Nilsimsa fuzzy hashes
/// are supported, but this will allow easy implementation for new hashes.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum FHVector<T>
where
    Vec<T>: Serialize + DeserializeOwned,
{
    /// Nilsimsa vector variant
    NilsimsaVector(Vec<T>),
}

impl FHVector<u8> {
    /// Convert a byte vector to a bit vector
    pub fn to_bits<const N: usize>(&self) -> Result<Vec<u8>, TryFromSliceError> {
        let vector = match self {
            Self::NilsimsaVector(v) => v,
        };

        Ok(vector
            .iter()
            .flat_map(|b| -> [u8; 8] { array::from_fn(|i| 1u8 & (b >> (7 - i))) })
            .collect::<Vec<u8>>())
    }
}

/*
    Allow to easily convert between FHVector, arrays and vec, based on size.
*/
impl<T: Serialize + Debug + DeserializeOwned> TryFrom<Vec<T>> for FHVector<T> {
    type Error = ();

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        match value.len() {
            NILSIMSA_VECTOR_SIZE_BYTES => Ok(FHVector::NilsimsaVector(value)),
            _ => Err(()),
        }
    }
}

impl From<[u8; 32]> for FHVector<u8> {
    fn from(value: [u8; 32]) -> FHVector<u8> {
        let vec = (0..NILSIMSA_VECTOR_SIZE_BYTES)
            .map(|i| {
                let index = i % (NILSIMSA_VECTOR_SIZE_BYTES / 2);
                if i < NILSIMSA_VECTOR_SIZE_BYTES / 2 {
                    value[index]
                } else {
                    0xff ^ value[index]
                }
            })
            .collect();

        FHVector::<_>::NilsimsaVector(vec)
    }
}
