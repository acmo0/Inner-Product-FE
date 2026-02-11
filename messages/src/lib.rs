use fe::{PublicKey, SecretKey};
use fuzzy_hashes::FHVector;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/*
    Messages between an Authority server and a compute server
*/
pub type GenerateInstanceRequest<T: DeserializeOwned> = Vec<FHVector<T>>;

#[derive(Serialize, Deserialize)]
pub struct GenerateInstanceResponse<const N: usize>(pub PublicKey<N>, pub Vec<SecretKey<N>>);

#[derive(Serialize, Deserialize)]
pub enum HashComparisonRequest {
    NILSIMSA,
}
