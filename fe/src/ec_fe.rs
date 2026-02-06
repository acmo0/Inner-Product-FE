#![allow(dead_code)]
use core::array;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use rand::{
    CryptoRng, SeedableRng,
    rngs::{StdRng, SysRng},
};

use crate::generic::{DdhFeCiphertext, DdhFeInstance, DdhFePublicKey, DdhFeSecretKey, MskItem};
use crate::traits::{FEInstance, FEPrivKey, FEPubKey};

// Type aliases (shared by both ec_fe.rs and ff_fe.rs)
pub type Instance<const N: usize> = DdhFeInstance<N, Scalar, RistrettoPoint>;
pub type PublicKey<const N: usize> = DdhFePublicKey<N, RistrettoPoint>;
pub type SecretKey<const N: usize> = DdhFeSecretKey<N, Scalar, RistrettoPoint>;
pub type CipherText<const N: usize> = DdhFeCiphertext<N, RistrettoPoint>;

// Useful to get a random master secret key element
impl MskItem<Scalar> {
    pub(crate) fn get_rand<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        MskItem {
            s: Scalar::random(rng),
            t: Scalar::random(rng),
        }
    }
}

/*
    Implements traits defined in traits.rs
*/
impl<const N: usize> FEInstance<N, RistrettoPoint, Scalar> for Instance<N> {
    fn setup() -> Self {
        // CS-PRNG
        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();

        // Init parameters
        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);

        // Init MSK/MPK
        let msk: [MskItem<Scalar>; N] = array::from_fn(|_i| MskItem::get_rand(&mut rng));
        let mpk: [RistrettoPoint; N] = array::from_fn(|i| msk[i].s * g + msk[i].t * h);

        DdhFeInstance { g, h, msk, mpk }
    }

    fn secret_key<T: Copy>(&self, vector: [T; N]) -> SecretKey<N>
    where
        Scalar: From<T>,
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
            sx: scal.0,
            tx: scal.1,
            x: array::from_fn(|i| Scalar::from(vector[i])),
        }
    }

    fn public_key<T: Copy>(&self) -> PublicKey<N>
    where
        Scalar: From<T>,
    {
        DdhFePublicKey {
            g: self.g,
            h: self.h,
            mpk: self.mpk,
        }
    }
}

impl<const N: usize, T> FEPubKey<N, T, RistrettoPoint> for PublicKey<N>
where
    Scalar: std::convert::From<T>,
    T: Copy,
{
    fn encrypt<R: CryptoRng + ?Sized>(&self, rng: &mut R, vector: [T; N]) -> CipherText<N> {
        let r = Scalar::random(rng);

        let c = r * self.g;
        let d = r * self.h;
        let e: [RistrettoPoint; N] =
            array::from_fn(|i| Scalar::from(vector[i]) * self.g + r * self.mpk[i]);

        DdhFeCiphertext { c, d, e }
    }
}

impl<const N: usize> FEPrivKey<N, RistrettoPoint, u16> for SecretKey<N> {
    fn decrypt(&self, ct: CipherText<N>, bound: u16) -> Option<u16> {
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
        let mut i = 0;
        let mut p = RistrettoPoint::identity();
        while i != bound && p != ex {
            i += 1;
            p += self.g
        }

        if i == bound { None } else { Some(i) }
    }
}
