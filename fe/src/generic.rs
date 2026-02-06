#[derive(Debug, Clone)]
pub(crate) struct MskItem<T> {
    pub(crate) s: T,
    pub(crate) t: T,
}

/// Generic structure representing a secret key for the FE scheme.
/// * `N` : size of the vector used in the scheme
/// * `T` : internal type to represent a vector element/scalar (not necessarily the one given by the user)
/// * `U` : internal type representing a group element used by the FE scheme
#[derive(Debug, Clone)]
pub struct DdhFeSecretKey<const N: usize, T, U> {
    pub(crate) g: U,
    pub(crate) sx: T,
    pub(crate) tx: T,
    pub(crate) x: [T; N],
}

/// Generic structure representing a public key for the FE scheme.
/// * `U` : internal type representing a group element used by the FE scheme
#[derive(Debug, Clone)]
pub struct DdhFePublicKey<const N: usize, U> {
    pub(crate) g: U,
    pub(crate) h: U,
    pub(crate) mpk: [U; N],
}

/// Generic structure representing a ciphertext for the FE scheme.
/// * `U` : internal type representing a group element used by the FE scheme
#[derive(Debug, Clone)]
pub struct DdhFeCiphertext<const N: usize, U> {
    pub(crate) c: U,
    pub(crate) d: U,
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
