use fe::{PublicKey, SecretKey};
use fuzzy_hashes::FHVector;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub type GenerateInstanceRequest<T: DeserializeOwned> = Vec<FHVector<T>>;

#[derive(Serialize)]
pub struct GenerateInstanceResponse<const N: usize>(pub PublicKey<N>, pub Vec<SecretKey<N>>);
