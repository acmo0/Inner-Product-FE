#![warn(missing_docs, rust_2018_idioms)]
//! Module containing implementation of fuzzy hashes and their related constants.

use core::array;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_big_array::BigArray;
use std::fmt::Debug;

/// Length of a Nilsimsa fuzzy hash
pub const NILSIMSA_FH_SIZE_BYTES: usize = 32;
/// Length in bytes of a Nilsimsa fuzzy hash vector
/// (i.e the fuzzy hash itself, and its opposite concatenated).
pub const NILSIMSA_VECTOR_SIZE_BYTES: usize = 64;
/// Length in bytes of a Nilsimsa fuzzy hash vector
/// (i.e the fuzzy hash itself, and its opposite concatenated).
pub const NILSIMSA_VECTOR_SIZE_BITS: usize = 512;

/// Enum representing a fuzzy hash vector. For now, only Nilsimsa fuzzy hashes
/// are supported, but this will allow easy implementation for new hashes.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum FHVector<T: Serialize + DeserializeOwned> {
    /// Nilsimsa vector variant
    #[serde(with = "BigArray")]
    NilsimsaVector([T; NILSIMSA_VECTOR_SIZE_BYTES]),
}

/*
    Allow to easily convert between FHVector, arrays and vec, based on size.
*/
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
            let index = i % (NILSIMSA_VECTOR_SIZE_BYTES / 2);
            if i < NILSIMSA_VECTOR_SIZE_BYTES / 2 {
                value[index]
            } else {
                0xff ^ value[index]
            }
        });

        FHVector::<_>::NilsimsaVector(vec)
    }
}
