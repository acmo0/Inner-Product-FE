use serde::{self, Deserialize, Serialize, Serializer, de::DeserializeOwned, ser::SerializeStruct};
use serde_big_array::BigArray;

#[derive(Debug, Clone)]
pub(crate) struct MskItem<T> {
    pub(crate) s: T,
    pub(crate) t: T,
}

/// Generic structure representing a secret key for the FE scheme.
/// * `N` : size of the vector used in the scheme
/// * `T` : internal type to represent a vector element/scalar (not necessarily the one given by the user)
/// * `U` : internal type representing a group element used by the FE scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdhFeSecretKey<const N: usize, T, U> {
    pub(crate) g: U,
    pub(crate) sx: T,
    pub(crate) tx: T,
    #[serde(with = "BigArray")]
    pub(crate) x: [T; N],
}

/// Generic structure representing a public key for the FE scheme.
/// * `U` : internal type representing a group element used by the FE scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdhFePublicKey<const N: usize, U> {
    pub(crate) g: U,
    pub(crate) h: U,
    #[serde(with = "BigArray")]
    pub(crate) mpk: [U; N],
}

/// Generic structure representing a ciphertext for the FE scheme.
/// * `U` : internal type representing a group element used by the FE scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdhFeCiphertext<const N: usize, U> {
    pub(crate) c: U,
    pub(crate) d: U,
    #[serde(with = "BigArray")]
    pub(crate) e: [U; N],
}

/// Generic structure representing a secret key for the FE scheme.
/// * `N` : size of the vector used in the scheme
/// * `T` : internal type to represent a vector element/scalar (not necessarily the one given by the user)
/// * `U` : internal type representing a group element used by the FE scheme
#[derive(Debug, Clone)]
pub struct DdhFeInstance<const N: usize, T, U> {
    pub(crate) g: U,
    pub(crate) h: U,
    pub(crate) msk: [MskItem<T>; N],
    pub(crate) mpk: [U; N],
}

/*
    "Compressed" variants to improve protocol efficiency
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedDdhFeSecretKey<T, U, V> {
    pub(crate) g: U,
    pub(crate) sx: T,
    pub(crate) tx: T,
    pub(crate) x: Vec<V>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedDdhFePublicKey<const N: usize, U> {
    pub(crate) g: U,
    pub(crate) h: U,
    #[serde(with = "BigArray")]
    pub(crate) mpk: [U; N],
}
