use core::array;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_big_array::BigArray;
use std::fmt::Debug;
/*mod nilsimsa;
pub use nilsimsa::*;*/

pub const NILSIMSA_VECTOR_SIZE_BYTES: usize = 64;
pub const NILSIMSA_VECTOR_SIZE_BITS: usize = 512;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum FHVector<T: Serialize + DeserializeOwned> {
    #[serde(with = "BigArray")]
    NilsimsaVector([T; NILSIMSA_VECTOR_SIZE_BYTES]),
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
            NILSIMSA_VECTOR_SIZE_BYTES => {
                let arr: [T; NILSIMSA_VECTOR_SIZE_BYTES] =
                    <[T; NILSIMSA_VECTOR_SIZE_BYTES]>::try_from(value).unwrap();
                Ok(FHVector::NilsimsaVector(arr))
            }
            _ => Err(()),
        }
    }
}

impl From<[u8; 32]> for FHVector<u8> {
    fn from(value: [u8; 32]) -> FHVector<u8> {
        let vec: [u8; NILSIMSA_VECTOR_SIZE_BYTES] = array::from_fn(|i| {
            let index = (i % (NILSIMSA_VECTOR_SIZE_BYTES / 2));
            if i < NILSIMSA_VECTOR_SIZE_BYTES / 2 {
                value[index]
            } else {
                0xff ^ value[index]
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
        let u = vec![0u8; NILSIMSA_VECTOR_SIZE_BYTES];
        let vec: FHVector<u8> = u.try_into().unwrap();
    }
}
