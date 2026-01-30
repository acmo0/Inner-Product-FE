#![allow(dead_code)]
use core::array;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use num_bigint::BigUint;
use num_traits::One;
use rand::{
    CryptoRng, SeedableRng,
    rngs::{StdRng, SysRng},
};

#[derive(Debug, Clone)]
struct MskItem {
    s: Scalar,
    t: Scalar,
}

impl MskItem {
    pub(crate) fn get_rand<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        MskItem {
            s: Scalar::random(rng),
            t: Scalar::random(rng),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DdhFeSecretKey<const N: usize> {
    g: RistrettoPoint,
    h: RistrettoPoint,
    sx: Scalar,
    tx: Scalar,
    x: [Scalar; N],
}

#[derive(Debug, Clone)]
pub struct DdhFePublicKey<const N: usize> {
    g: RistrettoPoint,
    h: RistrettoPoint,
    mpk: [RistrettoPoint; N],
}

#[derive(Debug, Clone)]
pub struct DdhFeCiphertext<const N: usize> {
    c: RistrettoPoint,
    d: RistrettoPoint,
    e: [RistrettoPoint; N],
}

#[derive(Debug, Clone)]
pub struct DdhFeInstance<const N: usize> {
    g: RistrettoPoint,
    h: RistrettoPoint,
    msk: [MskItem; N],
    mpk: [RistrettoPoint; N],
}

impl<const N: usize> DdhFeInstance<N> {
    pub fn new() -> Self {
        // CS-PRNG
        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();

        // Init parameters
        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);

        // Init MSK/MPK
        let msk: [MskItem; N] = array::from_fn(|_i| MskItem::get_rand(&mut rng));
        let mpk: [RistrettoPoint; N] = array::from_fn(|i| msk[i].s * g + msk[i].t * h);

        DdhFeInstance { g, h, msk, mpk }
    }

    pub fn secret_key_gen<T>(&self, vector: [T; N]) -> DdhFeSecretKey<N>
    where
        Scalar: std::convert::From<T>,
        T: std::marker::Copy,
    {
        let scal = self
            .msk
            .iter()
            .zip(vector)
            .map(|(e_i, v_i)| {
                (
                    e_i.s * <Scalar as From<T>>::from(v_i),
                    e_i.t * <Scalar as From<T>>::from(v_i),
                )
            })
            .reduce(|acc, e| (acc.0 + e.0, acc.1 + e.1))
            .unwrap();

        DdhFeSecretKey {
            g: self.g,
            h: self.h,
            sx: scal.0,
            tx: scal.1,
            x: array::from_fn(|i| Scalar::from(vector[i])),
        }
    }

    pub fn get_public_key(&self) -> DdhFePublicKey<N> {
        DdhFePublicKey {
            g: self.g,
            h: self.h,
            mpk: self.mpk,
        }
    }
}

impl<const N: usize> Default for DdhFeInstance<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DdhFePublicKey<N> {
    pub fn encrypt<T: Copy, R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        vector: [T; N],
    ) -> DdhFeCiphertext<N>
    where
        Scalar: std::convert::From<T>,
    {
        let r = Scalar::random(rng);

        let c = r * self.g;
        let d = r * self.h;
        let e: [RistrettoPoint; N] =
            array::from_fn(|i| Scalar::from(vector[i]) * self.g + r * self.mpk[i]);

        DdhFeCiphertext { c, d, e }
    }
}

impl<const N: usize> DdhFeSecretKey<N> {
    pub fn decrypt_bf(&self, ct: DdhFeCiphertext<N>, bound: BigUint) -> Option<BigUint> {
        let scalars: Vec<_> = self
            .x
            .iter()
            .chain(&[-self.sx, -self.tx])
            .cloned()
            .collect();
        let points: Vec<_> = ct.e.iter().chain(&[ct.c, ct.d]).cloned().collect();

        // Compute sum(E * xi) - C * sx - D * tx
        let ex = RistrettoPoint::multiscalar_mul(scalars, points);

        // BF to retrieve scalar product value
        let mut i = BigUint::ZERO;
        let mut p = RistrettoPoint::identity();
        while i != bound && p != ex {
            i += BigUint::one();
            p += self.g
        }

        if i == bound { None } else { Some(i) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{TestError, TestRunner};
    use rand::{
        SeedableRng,
        rngs::{StdRng, SysRng},
    };

    const N: usize = 512;

    fn fresh_instance() -> (DdhFeInstance<N>, DdhFePublicKey<N>) {
        println!("[test] Generating instance...");
        let instance = DdhFeInstance::new();
        let pk = instance.get_public_key();

        (instance, pk)
    }

    prop_compose! {
        fn two_random_vec()(secret_vec in prop::array::uniform(0u8..))
                         (secret_client_vec in prop::array::uniform(0u8..), secret_vec in Just(secret_vec))
                         -> ([u8; N], [u8; N]) {
            (secret_vec, secret_client_vec)
        }
    }
    prop_compose! {
        fn two_random_bitvec()(secret_vec in prop::array::uniform(0u8..2u8))
                         (secret_client_vec in prop::array::uniform(0u8..2u8), secret_vec in Just(secret_vec))
                         -> ([u8; N], [u8; N]) {
            (secret_vec, secret_client_vec)
        }
    }

    #[test]
    fn test_correctness() {
        let mut runner = TestRunner::default();
        let bound = BigUint::from(N);
        let (instance, pk) = fresh_instance();

        let result = runner.run(&two_random_vec(), |(secret_vec, secret_client_vec)| {
            let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
            let sk = instance.secret_key_gen(secret_vec);

            let ct = pk.encrypt(&mut rng, secret_client_vec);

            let scalar_prod = sk.decrypt_bf(ct, bound.clone());

            let expected: BigUint = secret_vec
                .iter()
                .zip(secret_client_vec)
                .map(|(a, b)| <u8 as Into<BigUint>>::into(*a) * <u8 as Into<BigUint>>::into(b))
                .fold(BigUint::ZERO, |acc, e: BigUint| acc + e);

            if expected >= bound {
                assert_eq!(scalar_prod, None);
            } else {
                assert_eq!(scalar_prod, Some(expected));
            }
            Ok(())
        });

        match result {
            Ok(()) => (),
            Err(TestError::Fail(_, value)) => println!("Found failing case {:?}", value),
            result => panic!("Unexpected result {:?}", result),
        }
    }

    #[test]
    fn test_bit_vectors() {
        let mut runner = TestRunner::default();
        let bound = BigUint::from(N);
        /*let secret_vec: [u8; N] = array::from_fn(|i| (i % 2) as u8);
        let secret_client_vec: [u8; N] = array::from_fn(|i| ((i + 1) % 2) as u8);
        */

        let (instance, pk) = fresh_instance();

        let result = runner.run(&two_random_bitvec(), |(secret_vec, secret_client_vec)| {
            let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
            let sk = instance.secret_key_gen(secret_vec);

            let ct = pk.encrypt(&mut rng, secret_client_vec);

            let scalar_prod = sk.decrypt_bf(ct, bound.clone());

            let expected: BigUint = secret_vec
                .iter()
                .zip(secret_client_vec)
                .map(|(a, b)| <u8 as Into<BigUint>>::into(*a) * <u8 as Into<BigUint>>::into(b))
                .fold(BigUint::ZERO, |acc, e: BigUint| acc + e);
            println!("Expected {:?}, found {:?}", expected, scalar_prod);
            if expected >= bound {
                assert_eq!(scalar_prod, None);
            } else {
                assert_eq!(scalar_prod, Some(expected));
            }
            Ok(())
        });

        match result {
            Ok(()) => (),
            Err(TestError::Fail(_, value)) => println!("Found failing case {:?}", value),
            result => panic!("Unexpected result {:?}", result),
        }
    }
}
