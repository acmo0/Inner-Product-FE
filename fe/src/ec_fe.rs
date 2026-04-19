#![allow(dead_code)]
use core::array;
use std::collections::HashMap;
use std::cmp::PartialEq;

use num_traits::identities::Zero;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use rand::{
    CryptoRng, SeedableRng,
    rngs::{StdRng, SysRng},
};

use crate::consts::RANDOM_PADDING_LEN;
use crate::generic::{
    CompressedDdhFePublicKey, CompressedDdhFeSecretKey, DdhFeCiphertext, DdhFeInstance,
    DdhFePublicKey, DdhFeSecretKey, MskItem,
};
use crate::traits::{FECipherText, FEInstance, FEPubKey, FESecretKey};
/*
    Type aliases (shared by both ec_fe.rs and ff_fe.rs)
*/
/// FE instance over Ristretto255 curve for arbitrary vector size.
pub type Instance<const N: usize> = DdhFeInstance<N, Scalar, RistrettoPoint>;
/// FE public key over Ristretto255 curve for arbitrary vector size.
pub type PublicKey<const N: usize> = DdhFePublicKey<N, RistrettoPoint>;
/// FE compressed public key to improve network bandwith and in-memory storage.
pub type CompressedPublicKey<const N: usize> = CompressedDdhFePublicKey<N, CompressedRistretto>;
/// FE secret key over Ristretto255 curve for arbitrary vector size.
pub type SecretKey<const N: usize> = DdhFeSecretKey<N, Scalar, RistrettoPoint>;
/// FE compressed secret key over Ristretto255 curve for arbitrary vector size. This is done to
/// (greatly) improve the efficiency of the network transmission and in-memory stoage
/// of the secret key structure.
pub type CompressedSecretKey = CompressedDdhFeSecretKey<Scalar, CompressedRistretto, u8>;
/// FE ciphertext over Ristretto255 curve for arbitrary vector size.
pub type CipherText<const N: usize> = DdhFeCiphertext<N, RistrettoPoint>;
/// Lookup table for discrete logarithm
pub type LogTable = HashMap<CompressedRistretto, u16>;

/// Implementation of From and TryFrom to allow easy compression/decompression
/// between a CompressedSecretKey and a SecretKey
impl<const N: usize> From<&SecretKey<N>> for CompressedSecretKey {
    fn from(value: &SecretKey<N>) -> CompressedSecretKey {
        let g = value.g.compress();
        let x_bytes: Vec<u8> = value
            .x
            .chunks_exact(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .map(|(i, b)| { 
                        if b.eq(&Scalar::ONE) { (1 << (7 - i)) } else if b.eq(&Scalar::ZERO) {0} else {panic!("Cannot serialize vector");}
                    })
                    .sum()
            })
            .collect();

        CompressedSecretKey {
            g,
            sx: value.sx,
            tx: value.tx,
            x: x_bytes,
        }
    }
}

impl<const N: usize> TryFrom<&CompressedSecretKey> for SecretKey<N> {
    type Error = ();

    fn try_from(value: &CompressedSecretKey) -> Result<Self, Self::Error> {
        if value.x.len() != N / 8 {
            return Err(());
        }

        let g = match value.g.decompress() {
            Some(p) => p,
            None => return Err(()),
        };

        let x: Vec<Scalar> = (0..N).map(|i| Scalar::from(1 & (value.x[i / 8] >> (7 - (i % 8))))).collect();

        Ok(SecretKey {
            g,
            sx: value.sx,
            tx: value.tx,
            x,
        })
    }
}

/// Implementation of From and TryFrom to allow easy compression/decompression
/// between a CompressedPublicKey and a PublicKey
impl<const N: usize> From<&PublicKey<N>> for CompressedPublicKey<N> {
    fn from(value: &PublicKey<N>) -> CompressedPublicKey<N> {
        let g = value.g.compress();
        let h = value.h.compress();
        let mpk: [CompressedRistretto; N] = array::from_fn(|i| value.mpk[i].compress());

        CompressedPublicKey { g, h, mpk }
    }
}

impl<const N: usize> TryFrom<&CompressedPublicKey<N>> for PublicKey<N> {
    type Error = ();

    fn try_from(value: &CompressedPublicKey<N>) -> Result<Self, Self::Error> {
        // Decompress the two generators
        let g = match value.g.decompress() {
            Some(p) => p,
            None => return Err(()),
        };
        let h = match value.h.decompress() {
            Some(p) => p,
            None => return Err(()),
        };

        let mut mpk: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); N];

        for i in 0..N {
            mpk[i] = match value.mpk[i].decompress() {
                Some(p) => p,
                None => return Err(()),
            };
        }

        Ok(PublicKey { g, h, mpk })
    }
}

impl<const N: usize> PublicKey<N> {
    pub fn get_gen(&self) -> RistrettoPoint {
        self.g
    }

    fn encrypt_scalar_vec<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        vector: [Scalar; N],
    ) -> CipherText<N> {
        let r = Scalar::random(rng);

        let c = r * self.g;
        let d = r * self.h;
        let e: Vec<RistrettoPoint> = (0..N).map(|i| vector[i] * self.g + r * self.mpk[i]).collect();

        DdhFeCiphertext { c, d, e }
    }
}
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
        let msk: Vec<MskItem<Scalar>> = vec![MskItem::get_rand(&mut rng); N];
        let mpk: Vec<RistrettoPoint> = (0..N).map(|i| msk[i].s * g + msk[i].t * h).collect();

        DdhFeInstance { g, h, msk, mpk }
    }

    fn secret_key<T: Copy + Zero + PartialEq>(&self, vector: &[T]) -> SecretKey<N>
    where
        Scalar: From<T>,
    {
        let scal = self
            .msk
            .iter()
            .zip(vector)
            .map(|(e_i, v_i)| {
                // As vectors are binary ones
                if v_i == &T::zero() {
                    (
                        Scalar::ZERO,
                        Scalar::ZERO,
                    )

                } else {
                    (
                        e_i.s,
                        e_i.t,
                    )
                }
            })
            .reduce(|acc, e| (acc.0 + e.0, acc.1 + e.1))
            .unwrap();

        DdhFeSecretKey {
            g: self.g,
            sx: scal.0,
            tx: scal.1,
            x: vector.iter().map(|&v| Scalar::from(v)).collect(),
        }
    }

    fn public_key<T: Copy>(&self) -> PublicKey<N>
    where
        Scalar: From<T>,
    {
        DdhFePublicKey {
            g: self.g,
            h: self.h,
            mpk: self.mpk.to_vec(),
        }
    }
}

impl<const N: usize, T> FEPubKey<N, T, RistrettoPoint, Scalar> for PublicKey<N>
where
    Scalar: std::convert::From<T>,
    T: Copy, 
{
    fn encrypt<R: CryptoRng + ?Sized>(&self, rng: &mut R, vector: [T; N]) -> CipherText<N> {
        let v: [Scalar; N] = array::from_fn(|i| Scalar::from(vector[i]));

        self.encrypt_scalar_vec(rng, v)
    }

    fn encrypt_random_pad<const L: usize, R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        vector: [T; L],
    ) -> (CipherText<N>, [Scalar; RANDOM_PADDING_LEN]) {
        assert!(L + RANDOM_PADDING_LEN == N);

        let random_padding: [Scalar; RANDOM_PADDING_LEN] = array::from_fn(|_i| Scalar::random(rng));
        let vector_with_padding: [Scalar; N] = array::from_fn(|i| {
            if i < L {
                Scalar::from(vector[i])
            } else {
                random_padding[i - L]
            }
        });

        (
            self.encrypt_scalar_vec(rng, vector_with_padding),
            random_padding,
        )
    }
}

impl<const N: usize> FECipherText<RistrettoPoint> for CipherText<N> {
    fn get_c(&self) -> RistrettoPoint {
        self.c
    }
    fn get_d(&self) -> RistrettoPoint {
        self.d
    }
    fn get_e(&self) -> &[RistrettoPoint] {
        &self.e
    }
}

impl<const N: usize> FESecretKey<N, RistrettoPoint, u16> for SecretKey<N> {
    fn decrypt(&self, ct: impl FECipherText<RistrettoPoint>, bound: u16) -> Option<u16> {
        let ex = self.partial_decrypt(&ct);

        // BF to retrieve scalar product value
        let mut ip = bound / 2;
        let mut im = bound / 2;
        let mut pp = Scalar::from(ip) * self.g;
        let mut pm = pp;
        while ip <= bound {
            if pp == ex {
                return Some(ip);
            } else {
                ip += 1;
                pp += self.g;
            }

            if pm == ex {
                return Some(im);
            } else {
                im = im.saturating_sub(1);
                pm -= self.g;
            }
        }

        None
    }

    fn partial_decrypt(&self, ct: &impl FECipherText<RistrettoPoint>) -> RistrettoPoint {
        let scalars: Vec<_> = self
            .x
            .iter()
            .chain(&[-self.sx, -self.tx])
            .cloned()
            .collect();
        let points: Vec<_> = ct
            .get_e()
            .iter()
            .chain(&[ct.get_c(), ct.get_d()])
            .cloned()
            .collect();

        // Compute sum(E * xi) - C * sx - D * tx
        RistrettoPoint::multiscalar_mul(scalars, points)
    }
}

/// Generate a lookup table : [0]G, [1]G, ..., [bound]G for a given bound and a given G.
pub fn generate_table(generator: RistrettoPoint, bound: u16) -> LogTable {
    let mut table = HashMap::new();
    let mut p = RistrettoPoint::identity();

    for i in 0..bound {
        table.insert(p.compress(), i);
        p += generator;
    }

    table
}
