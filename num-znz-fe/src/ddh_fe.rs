#![allow(dead_code)]
use core::array;

use num_bigint::{BigUint, RandBigInt};
use num_traits::identities::One;
use rand::{SeedableRng, rngs::StdRng};
use std::clone::Clone;
use std::ops::Mul;

use crate::consts;

#[derive(Debug, Clone)]
struct MskItem {
    s: BigUint,
    t: BigUint,
}

impl MskItem {
    pub(crate) fn get_rand<T>(rng: &mut T, lbound: &BigUint, ubound: &BigUint) -> Self
    where
        T: RandBigInt,
    {
        MskItem {
            s: rng.gen_biguint_range(lbound, ubound),
            t: rng.gen_biguint_range(lbound, ubound),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DdhFeSecretKey<T, const N: usize> {
    order: BigUint,
    g: BigUint,
    h: BigUint,
    sx: BigUint,
    tx: BigUint,
    x: [T; N],
}

#[derive(Debug, Clone)]
pub struct DdhFePublicKey<const N: usize> {
    order: BigUint,
    g: BigUint,
    h: BigUint,
    mpk: [BigUint; N],
}

#[derive(Debug, Clone)]
pub struct DdhFeCiphertext<const N: usize> {
    c: BigUint,
    d: BigUint,
    e: [BigUint; N],
}

#[derive(Debug, Clone)]
pub struct DdhFeInstance<const N: usize> {
    order: BigUint,
    g: BigUint,
    h: BigUint,
    msk: [MskItem; N],
    mpk: [BigUint; N],
}

impl<const N: usize> DdhFeInstance<N> {
    pub fn new_from_dhg15() -> Self {
        // CS-PRNG
        let mut rng = StdRng::from_entropy();

        // Init parameters
        let cst_2: BigUint = 2u8.into();
        let order = BigUint::from_slice(&consts::DH15_PRIME);
        let max = &order - 1u8;
        let g = rng.gen_biguint_range(&cst_2, &max);
        let h = rng.gen_biguint_range(&cst_2, &max);

        // Init MSK/MPK
        let msk: [MskItem; N] = array::from_fn(|_i| MskItem::get_rand(&mut rng, &cst_2, &max));
        let mpk: [BigUint; N] = array::from_fn(|i| {
            (g.modpow(&msk[i].s, &order) * h.modpow(&msk[i].t, &order)) % &order
        });

        DdhFeInstance {
            order,
            g,
            h,
            msk,
            mpk,
        }
    }

    pub fn secret_key_gen<T>(&self, vector: [T; N]) -> DdhFeSecretKey<T, N>
    where
        for<'a> &'a BigUint: Mul<T, Output = BigUint>,
        T: std::marker::Copy,
    {
        let scal = self
            .msk
            .iter()
            .zip(vector)
            .map(|(e_i, v_i)| (&e_i.s * v_i, &e_i.t * v_i))
            .reduce(|acc, e| (acc.0 + e.0, acc.1 + e.1))
            .unwrap();

        DdhFeSecretKey {
            order: self.order.clone(),
            g: self.g.clone(),
            h: self.h.clone(),
            sx: scal.0,
            tx: scal.1,
            x: vector,
        }
    }

    pub fn get_public_key(&self) -> DdhFePublicKey<N> {
        DdhFePublicKey {
            order: self.order.clone(),
            g: self.g.clone(),
            h: self.h.clone(),
            mpk: self.mpk.clone(),
        }
    }
}

impl<const N: usize> DdhFePublicKey<N> {
    pub fn encrypt<T: Copy>(&self, vector: [T; N]) -> DdhFeCiphertext<N>
    where
        BigUint: std::convert::From<T>,
    {
        let mut rng = StdRng::from_entropy();
        let r = rng.gen_biguint_below(&(&self.order - BigUint::one()));

        let c = self.g.modpow(&r, &self.order);
        let d = self.h.modpow(&r, &self.order);
        let e: [BigUint; N] = array::from_fn(|i| {
            &self.g.modpow(&vector[i].into(), &self.order) * &self.mpk[i].modpow(&r, &self.order)
        });

        DdhFeCiphertext { c, d, e }
    }
}

impl<T: std::marker::Copy, const N: usize> DdhFeSecretKey<T, N>
where
    BigUint: std::convert::From<T>,
{
    pub fn decrypt_bf(&self, ct: DdhFeCiphertext<N>, bound: BigUint) -> Option<BigUint> {
        let ex =
            ct.e.iter()
                .zip(self.x)
                .fold(BigUint::one(), |acc, (ei, xi)| {
                    (acc * ei.modpow(&xi.into(), &self.order)) % &self.order
                })
                * (ct.c.modpow(&self.sx, &self.order) * ct.d.modpow(&self.tx, &self.order))
                    .modpow(&(&self.order - 2u8), &self.order)
                % &self.order;

        let mut i = BigUint::ZERO;
        let mut p = BigUint::one();
        while i < bound && p != ex {
            i += BigUint::one();
            p *= &self.g;
            p %= &self.order;
        }

        if i == bound { None } else { Some(i) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{TestError, TestRunner};

    const INSTANCE_SIZE: usize = 512;
    const N: usize = 512;

    fn fresh_instance() -> (DdhFeInstance<N>, DdhFePublicKey<N>) {
        println!("[test] Generating instance...");
        let instance = DdhFeInstance::new_from_dhg15();
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
        let bound: BigUint = 1024u16.into();

        let (instance, pk) = fresh_instance();

        let result = runner.run(&two_random_vec(), |(secret_vec, secret_client_vec)| {
            let sk = instance.secret_key_gen(secret_vec);

            let ct = pk.encrypt(secret_client_vec);

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
        let bound: BigUint = 1024u16.into();
        /*let secret_vec: [u8; N] = array::from_fn(|i| (i % 2) as u8);
        let secret_client_vec: [u8; N] = array::from_fn(|i| ((i + 1) % 2) as u8);
        */

        let (instance, pk) = fresh_instance();

        let result = runner.run(&two_random_bitvec(), |(secret_vec, secret_client_vec)| {
            let sk = instance.secret_key_gen(secret_vec);

            let ct = pk.encrypt(secret_client_vec);

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
}
