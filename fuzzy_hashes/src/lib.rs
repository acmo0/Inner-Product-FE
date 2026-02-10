use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_big_array::BigArray;
use std::fmt::Debug;

/*mod nilsimsa;
pub use nilsimsa::*;*/

pub const NILSIMSA_VECTOR_SIZE: usize = 512;

#[derive(Debug, Copy, Clone, Deserialize)]

pub enum FHVector<T: DeserializeOwned> {
    #[serde(with = "BigArray")]
    NilsimsaVector([T; NILSIMSA_VECTOR_SIZE]),
}

/*
impl<T: Debug + DeserializeOwned> FHVector<T> {
    fn vector<const N: usize>(&self) -> [T; N] {
        match self {
            FHVector::<T>::NilsimsaVector(v) => v.clone(),
            FHVector::<T>::Vec256(v) => v.clone(),
        }
    }
}*/

impl<T: Debug + DeserializeOwned> TryFrom<Vec<T>> for FHVector<T> {
    type Error = ();

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        match value.len() {
            NILSIMSA_VECTOR_SIZE => {
                let arr: [T; NILSIMSA_VECTOR_SIZE] =
                    <[T; NILSIMSA_VECTOR_SIZE]>::try_from(value).unwrap();
                Ok(FHVector::NilsimsaVector(arr))
            }
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dummy_test() {
        let u = vec![0u8; NILSIMSA_VECTOR_SIZE];
        let vec: FHVector<u8> = u.try_into().unwrap();
    }
}
