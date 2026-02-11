use fe::{CompressedSecretKey, PublicKey, SecretKey};
use fuzzy_hashes::FHVector;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/*
    Messages between an Authority server and a compute server
*/
pub type GenerateInstanceRequest<T: DeserializeOwned> = Vec<FHVector<T>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateInstanceResponse<const N: usize>(pub PublicKey<N>, pub Vec<CompressedSecretKey>);

impl<const N: usize> GenerateInstanceResponse<N> {
    pub fn decompress(&self) -> Result<(PublicKey<N>, Vec<SecretKey<N>>), ()> {
        let pub_key = self.0.clone();

        let mut vec_uncompressed = vec![];
        for v in self.1.iter() {
            match SecretKey::<N>::try_from(v) {
                Ok(vec) => vec_uncompressed.push(vec),
                Err(_) => return Err(()),
            }
        }
        Ok((pub_key, vec_uncompressed))
    }
}

impl<const N: usize> From<(PublicKey<N>, Vec<SecretKey<N>>)> for GenerateInstanceResponse<N> {
    fn from(value: (PublicKey<N>, Vec<SecretKey<N>>)) -> GenerateInstanceResponse<N> {
        let compressed_sk = value
            .1
            .iter()
            .map(|v| CompressedSecretKey::from(v))
            .collect();
        GenerateInstanceResponse(value.0, compressed_sk)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HashComparisonRequest {
    NILSIMSA,
}
