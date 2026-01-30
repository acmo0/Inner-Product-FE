#![allow(dead_code)]
use core::array;

use malachite::base::num::arithmetic::traits::{ModMul, ModMulAssign, ModPow};
use malachite::base::num::basic::traits::Zero;
use malachite::base::random::Seed;
use malachite::natural::Natural;
use malachite::natural::random::{self, UniformRandomNaturalRange};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::clone::Clone;

use crate::consts;

#[derive(Debug, Clone)]
struct MskItem {
    s: Natural,
    t: Natural,
}

impl MskItem {
    pub(crate) fn get_rand(rng: &mut UniformRandomNaturalRange) -> Self {
        MskItem {
            s: rng
                .next()
                .expect("Unable to generate a random secret key item"),
            t: rng
                .next()
                .expect("Unable to generate a random secret key item"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DdhFeSecretKey<T, const N: usize> {
    order: Natural,
    g: Natural,
    h: Natural,
    sx: Natural,
    tx: Natural,
    x: [T; N],
}

#[derive(Debug, Clone)]
pub struct DdhFePublicKey<const N: usize> {
    order: Natural,
    g: Natural,
    h: Natural,
    mpk: [Natural; N],
}

#[derive(Debug, Clone)]
pub struct DdhFeCiphertext<const N: usize> {
    c: Natural,
    d: Natural,
    e: [Natural; N],
}

#[derive(Debug, Clone)]
pub struct DdhFeInstance<const N: usize> {
    order: Natural,
    g: Natural,
    h: Natural,
    msk: [MskItem; N],
    mpk: [Natural; N],
}

impl<const N: usize> DdhFeInstance<N> {
    pub fn new_from_dhg15() -> Self {
        let order = Natural::from_limbs_desc(&consts::DH15_PRIME);

        Self::generate_instance_for_order(order)
    }

    fn generate_instance_for_order(order: Natural) -> Self {
        // PRNG init
        let mut seeder = StdRng::from_os_rng();
        let seed = Seed::from_bytes(array::from_fn(|_| seeder.random::<u8>()));
        let mut rng = random::uniform_random_natural_range(seed, consts::CST2, order.clone());

        // Init parameters
        let g = rng.next().expect("Unable to generate a random generator");
        let h = rng.next().expect("Unable to generate a random generator");

        // Init MSK/MPK
        let msk: [MskItem; N] = array::from_fn(|_i| MskItem::get_rand(&mut rng));
        let mpk: [Natural; N] = array::from_fn(|i| {
            g.clone()
                .mod_pow(&msk[i].s, &order)
                .mod_mul(h.clone().mod_pow(&msk[i].t, &order), &order)
        });

        DdhFeInstance {
            order,
            g,
            h,
            msk,
            mpk,
        }
    }

    pub fn secret_key_gen(&self, vector: [Natural; N]) -> DdhFeSecretKey<Natural, N> {
        let scal = self
            .msk
            .iter()
            .zip(vector.clone())
            .map(|(e_i, v_i)| (&e_i.s * &v_i, &e_i.t * v_i))
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
    pub fn encrypt(&self, vector: [Natural; N]) -> DdhFeCiphertext<N> {
        let mut seeder = StdRng::from_os_rng();
        let seed = Seed::from_bytes(array::from_fn(|_| seeder.random::<u8>()));
        let mut rng = random::uniform_random_natural_range(seed, consts::CST2, self.order.clone());

        let r = rng
            .next()
            .expect("Unable to generate a random value for encryption");

        let c = self.g.clone().mod_pow(&r, &self.order);
        let d = self.h.clone().mod_pow(&r, &self.order);
        let e: [Natural; N] = array::from_fn(|i| {
            self.g
                .clone()
                .mod_pow(&vector[i], &self.order)
                .mod_mul(&self.mpk[i].clone().mod_pow(&r, &self.order), &self.order)
        });

        DdhFeCiphertext { c, d, e }
    }
}

impl<const N: usize> DdhFeSecretKey<Natural, N> {
    pub fn decrypt_bf(&self, ct: DdhFeCiphertext<N>, bound: Natural) -> Option<Natural> {
        let ex =
            ct.e.iter()
                .zip(self.x.clone())
                .fold(Natural::const_from(1), |acc, (ei, xi)| {
                    acc.mod_mul(ei.mod_pow(xi, &self.order), &self.order)
                })
                .mod_mul(
                    ct.c.mod_pow(&self.sx, &self.order)
                        .mod_mul(ct.d.mod_pow(&self.tx, &self.order), &self.order)
                        .mod_pow(&self.order - consts::CST2, &self.order),
                    &self.order,
                );

        let mut i = Natural::ZERO;
        let mut p = Natural::from(1u8);
        while i < bound && p != ex {
            i += consts::CST1;
            p.mod_mul_assign(&self.g, &self.order);
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
        let mut pk = instance.get_public_key();

        (instance, pk)
    }

    prop_compose! {
        fn two_random_vec()(secret_vec in prop::array::uniform::<std::ops::RangeFrom<u8>, N>(0u8..))
                         (secret_client_vec in prop::array::uniform::<std::ops::RangeFrom<u8>, N>(0u8..), secret_vec in Just::<[u8; N]>(secret_vec))
                         -> ([Natural; N], [Natural; N]) {
            let mut output_secret_vec: [Natural; N] = array::from_fn(|_| Natural::ZERO);
            let mut output_secret_client_vec: [Natural; N] = array::from_fn(|_| Natural::ZERO);

            for (i, e) in secret_vec.iter().enumerate() {
                output_secret_vec[i] = Natural::from(*e);
            }

            for (i, e) in secret_client_vec.iter().enumerate() {
                output_secret_client_vec[i] = Natural::from(*e);
            }

            (output_secret_vec, output_secret_client_vec)
        }
    }
    prop_compose! {
        fn two_random_bitvec()(secret_vec in prop::array::uniform::<std::ops::Range<u8>, N>(0u8..1u8))
                         (secret_client_vec in prop::array::uniform::<std::ops::Range<u8>, N>(0u8..1u8), secret_vec in Just::<[u8; N]>(secret_vec))
                         -> ([Natural; N], [Natural; N]) {
            let mut output_secret_vec: [Natural; N]= array::from_fn(|_| Natural::ZERO);
            let mut output_secret_client_vec: [Natural; N]= array::from_fn(|_| Natural::ZERO);

            for (i, e) in secret_vec.iter().enumerate() {
                output_secret_vec[i] = Natural::from(*e);
            }

            for (i, e) in secret_client_vec.iter().enumerate() {
                output_secret_client_vec[i] = Natural::from(*e);
            }

            (output_secret_vec, output_secret_client_vec)
        }
    }

    #[test]
    fn test_correctness() {
        let mut runner = TestRunner::default();
        let bound: Natural = 1024u16.into();

        let (instance, mut pk) = fresh_instance();

        let result = runner.run(&two_random_vec(), |(secret_vec, secret_client_vec)| {
            let sk = instance.secret_key_gen(secret_vec.clone());

            let ct = pk.encrypt(secret_client_vec.clone());

            let scalar_prod = sk.decrypt_bf(ct, bound.clone());

            let expected: Natural = secret_vec
                .iter()
                .zip(secret_client_vec)
                .map(|(a, b)| a * b)
                .fold(Natural::ZERO, |acc, e: Natural| acc + e);

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
        let bound: Natural = 1024u16.into();
        /*let secret_vec: [u8; N] = array::from_fn(|i| (i % 2) as u8);
        let secret_client_vec: [u8; N] = array::from_fn(|i| ((i + 1) % 2) as u8);
        */

        let (instance, mut pk) = fresh_instance();

        let result = runner.run(&two_random_bitvec(), |(secret_vec, secret_client_vec)| {
            let sk = instance.secret_key_gen(secret_vec.clone());

            let ct = pk.encrypt(secret_client_vec.clone());

            let scalar_prod = sk.decrypt_bf(ct, bound.clone());

            let expected: Natural = secret_vec
                .iter()
                .zip(secret_client_vec)
                .map(|(a, b)| a * b)
                .fold(Natural::ZERO, |acc, e: Natural| acc + e);

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
