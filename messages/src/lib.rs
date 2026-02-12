#![warn(missing_docs, rust_2018_idioms)]

//! Module containing all the messages exchanged over the network
// between the Authority, the Compute Server and the Client.
use anyhow::{Error, Result, anyhow};
use fe::{CipherText, CompressedSecretKey, PublicKey, SecretKey};
use fuzzy_hashes::FHVector;
use serde::{Deserialize, Serialize};

/*
    Messages between an Authority and a Compute server
*/
/// Request send to the Authority by the Compute server to generate a fresh instance,
/// generate a public key and encrypt the provided vectors in the GenerateInstanceRequest.
pub type GenerateInstanceRequest<T> = Vec<FHVector<T>>;

/// Reply send to the Compute server by the Authority. It contains the secret keys for the
/// previously requested vectors and the associated public key.
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateInstanceResponse<const N: usize>(pub PublicKey<N>, pub Vec<CompressedSecretKey>);

impl<const N: usize> GenerateInstanceResponse<N> {
    /// "Decompress" the response to retrieve the PublicKey and the SecretKey with
    /// the correct types for the underlying FE implementation.
    pub fn decompress(&self) -> Result<(PublicKey<N>, Vec<SecretKey<N>>), Error> {
        let pub_key = self.0.clone();

        let mut vec_uncompressed = vec![];
        for v in self.1.iter() {
            match SecretKey::<N>::try_from(v) {
                Ok(vec) => vec_uncompressed.push(vec),
                Err(_) => {
                    return Err(anyhow!(
                        "Unable to decompress a vector from the authority, abort."
                    ));
                }
            }
        }
        Ok((pub_key, vec_uncompressed))
    }
}

impl<const N: usize> From<(PublicKey<N>, Vec<SecretKey<N>>)> for GenerateInstanceResponse<N> {
    /// Allow to easily "compress" the public key and the secret keys for network transmission.
    fn from(value: (PublicKey<N>, Vec<SecretKey<N>>)) -> GenerateInstanceResponse<N> {
        let compressed_sk = value.1.iter().map(CompressedSecretKey::from).collect();
        GenerateInstanceResponse(value.0, compressed_sk)
    }
}

/*
    Messages between a Client and a Compute server.
*/
/// Request send to the compute server by the client
/// to indicate which fuzzy hash to compare.
#[derive(Debug, Serialize, Deserialize)]
pub enum HashComparisonRequest {
    /// Indicate that the client wants to compare Nilsimsa fuzzy hash.
    NILSIMSA,
}

/// Request to the client to encrypt its hash using
/// the given public key in the request
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionRequest<const N: usize, T> {
    /// Field containing the public key to encrypt the fuzzy hash
    pub pk: Option<PublicKey<N>>,
    /// Potential similarity score of any computed by the server
    /// before sending that encryption request
    pub similarity_score: Option<T>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EncryptionResponse<const N: usize> {
    /// The client send an encrypted fuzzy hash to compare
    EncryptedVector(CipherText<N>),
    EndOfComparison,
}
