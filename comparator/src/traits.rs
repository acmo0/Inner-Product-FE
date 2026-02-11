/// Trait to compute a similarity score from a FE secret key and a FE ciphertext.
pub trait Comparator<const N: usize, T, E> {
    fn compare(&self, encrypted_vector: E) -> T;
}
