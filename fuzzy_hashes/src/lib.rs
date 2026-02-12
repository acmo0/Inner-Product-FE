#![warn(missing_docs, rust_2018_idioms)]
//! Module containing implementation of fuzzy hashes and their related constants.

use core::array;
use core::array::TryFromSliceError;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_big_array::BigArray;
use std::fmt::Debug;
use std::ops::BitAnd;
use std::ops::Shr;

mod nilsimsa;
pub use nilsimsa::Nilsimsa;

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

impl FHVector<u8> {
    /// Convert a byte vector to a bit vector
    pub fn to_bits<const N: usize>(&self) -> Result<[u8; N], TryFromSliceError> {
        let vector = match self {
            Self::NilsimsaVector(v) => v,
        };

        vector
            .iter()
            .flat_map(|b| -> [u8; 8] { array::from_fn(|i| 1u8 & (b >> (7 - i))) })
            .collect::<Vec<u8>>()
            .as_slice()
            .try_into()
    }
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
