use core::array;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_big_array::BigArray;
use std::fmt::Debug;
/*mod nilsimsa;
pub use nilsimsa::*;*/

pub const NILSIMSA_VECTOR_SIZE: usize = 512;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum FHVector<T: Serialize + DeserializeOwned> {
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

impl<T: Serialize + Debug + DeserializeOwned> TryFrom<Vec<T>> for FHVector<T> {
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

impl From<[u8; 32]> for FHVector<u8> {
    fn from(value: [u8; 32]) -> FHVector<u8> {
        let vec: [u8; NILSIMSA_VECTOR_SIZE] = array::from_fn(|i| {
            let index = (i % (NILSIMSA_VECTOR_SIZE / 2)) / 8;
            let b = (value[index] >> (7 - (i % 8))) & 1;
            if i < NILSIMSA_VECTOR_SIZE / 2 {
                b
            } else {
                1 ^ b
            }
        });

        FHVector::<_>::NilsimsaVector(vec)
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
