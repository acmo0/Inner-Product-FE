#![allow(dead_code)]
use core::array;
use std::clone::Clone;

use malachite::base::num::arithmetic::traits::{ModMul, ModMulAssign, ModPow};
use malachite::base::random::Seed;
use malachite::natural::Natural;
use malachite::natural::random::{self, UniformRandomNaturalRange};
use rand::{
    CryptoRng, RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};

use crate::consts;
use crate::generic::{DdhFeCiphertext, DdhFeInstance, DdhFePublicKey, DdhFeSecretKey, MskItem};
use crate::traits::{FEInstance, FEPrivKey, FEPubKey};

lazy_static::lazy_static! {
    static ref DH15_PRIME: Natural = Natural::from_limbs_desc(&consts::DH15_PRIME_LIMBS);
}

// Useful to get a random master secret key element
impl MskItem<Natural> {
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

// Type aliases (shared by both ec_fe.rs and ff_fe.rs)
pub type Instance<const N: usize> = DdhFeInstance<N, Natural, Natural>;
pub type PublicKey<const N: usize> = DdhFePublicKey<N, Natural>;
pub type SecretKey<const N: usize> = DdhFeSecretKey<N, Natural, Natural>;
pub type CipherText<const N: usize> = DdhFeCiphertext<N, Natural>;

/*
    Implements traits defined in traits.rs
*/
impl<const N: usize> FEInstance<N, Natural, Natural> for Instance<N> {
    fn setup() -> Self {
        // PRNG
        let mut seeder = StdRng::try_from_rng(&mut SysRng).unwrap();
        let seed = Seed::from_bytes(array::from_fn(|_| seeder.random::<u8>()));
        let mut rng = random::uniform_random_natural_range(seed, consts::CST2, DH15_PRIME.clone());

        // Init parameters
        let g = rng.next().expect("Unable to generate a random generator");
        let h = rng.next().expect("Unable to generate a random generator");

        // Init MSK/MPK
        let msk: [MskItem<Natural>; N] = array::from_fn(|_i| MskItem::get_rand(&mut rng));
        let mpk: [Natural; N] = array::from_fn(|i| {
            g.clone()
                .mod_pow(&msk[i].s, &*DH15_PRIME)
                .mod_mul(h.clone().mod_pow(&msk[i].t, &*DH15_PRIME), &*DH15_PRIME)
        });

        DdhFeInstance { g, h, msk, mpk }
    }

    fn secret_key<T: Copy>(&self, vector: [T; N]) -> SecretKey<N>
    where
        Natural: From<T>,
    {
        let scal = vector
            .iter()
            .map(|v_i| Natural::from(*v_i))
            .zip(&self.msk)
            .map(|(v_i, e_i)| (&e_i.s * &v_i, &e_i.t * v_i))
            .reduce(|acc, e| (acc.0 + e.0, acc.1 + e.1))
            .unwrap();

        DdhFeSecretKey {
            g: self.g.clone(),
            sx: scal.0,
            tx: scal.1,
            x: array::from_fn(|i| Natural::from(vector[i])),
        }
    }

    fn public_key<T: Copy>(&self) -> PublicKey<N>
    where
        Natural: From<T>,
    {
        DdhFePublicKey {
            g: self.g.clone(),
            h: self.h.clone(),
            mpk: self.mpk.clone(),
        }
    }
}

impl<const N: usize, T> FEPubKey<N, T, Natural> for PublicKey<N>
where
    Natural: From<T>,
    T: Copy,
{
    fn encrypt<R: CryptoRng + ?Sized>(&self, seeder: &mut R, vector: [T; N]) -> CipherText<N> {
        let seed = Seed::from_bytes(array::from_fn(|_| seeder.random::<u8>()));
        let mut rng = random::uniform_random_natural_range(seed, consts::CST2, DH15_PRIME.clone());

        let r = rng
            .next()
            .expect("Unable to generate a random value for encryption");

        let c = self.g.clone().mod_pow(&r, &*DH15_PRIME);
        let d = self.h.clone().mod_pow(&r, &*DH15_PRIME);
        let e: [Natural; N] = array::from_fn(|i| {
            self.g
                .clone()
                .mod_pow(Natural::from(vector[i]), &*DH15_PRIME)
                .mod_mul(&self.mpk[i].clone().mod_pow(&r, &*DH15_PRIME), &*DH15_PRIME)
        });

        DdhFeCiphertext { c, d, e }
    }
}

impl<const N: usize> FEPrivKey<N, Natural, u16> for SecretKey<N> {
    fn decrypt(&self, ct: CipherText<N>, bound: u16) -> Option<u16> {
        let ex =
            ct.e.iter()
                .zip(self.x.clone())
                .fold(Natural::const_from(1), |acc, (ei, xi)| {
                    acc.mod_mul(ei.mod_pow(xi, &*DH15_PRIME), &*DH15_PRIME)
                })
                .mod_mul(
                    ct.c.mod_pow(&self.sx, &*DH15_PRIME)
                        .mod_mul(ct.d.mod_pow(&self.tx, &*DH15_PRIME), &*DH15_PRIME)
                        .mod_pow(&*DH15_PRIME - consts::CST2, &*DH15_PRIME),
                    &*DH15_PRIME,
                );

        let mut i = 0u16;
        let mut p = Natural::from(1u8);
        while i < bound && p != ex {
            i += 1;
            p.mod_mul_assign(&self.g, &*DH15_PRIME);
        }

        if i == bound { None } else { Some(i) }
    }
}
