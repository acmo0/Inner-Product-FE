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

//https://www.ietf.org/rfc/rfc3526.txt
const DH15_PRIME_LIMBS: [u64; 48] = [
    0xFFFFFFFFFFFFFFFF,
    0xC90FDAA22168C234,
    0xC4C6628B80DC1CD1,
    0x29024E088A67CC74,
    0x020BBEA63B139B22,
    0x514A08798E3404DD,
    0xEF9519B3CD3A431B,
    0x302B0A6DF25F1437,
    0x4FE1356D6D51C245,
    0xE485B576625E7EC6,
    0xF44C42E9A637ED6B,
    0x0BFF5CB6F406B7ED,
    0xEE386BFB5A899FA5,
    0xAE9F24117C4B1FE6,
    0x49286651ECE45B3D,
    0xC2007CB8A163BF05,
    0x98DA48361C55D39A,
    0x69163FA8FD24CF5F,
    0x83655D23DCA3AD96,
    0x1C62F356208552BB,
    0x9ED529077096966D,
    0x670C354E4ABC9804,
    0xF1746C08CA18217C,
    0x32905E462E36CE3B,
    0xE39E772C180E8603,
    0x9B2783A2EC07A28F,
    0xB5C55DF06F4C52C9,
    0xDE2BCBF695581718,
    0x3995497CEA956AE5,
    0x15D2261898FA0510,
    0x15728E5A8AAAC42D,
    0xAD33170D04507A33,
    0xA85521ABDF1CBA64,
    0xECFB850458DBEF0A,
    0x8AEA71575D060C7D,
    0xB3970F85A6E1E4C7,
    0xABF5AE8CDB0933D7,
    0x1E8C94E04A25619D,
    0xCEE3D2261AD2EE6B,
    0xF12FFA06D98A0864,
    0xD87602733EC86A64,
    0x521F2B18177B200C,
    0xBBE117577A615D6C,
    0x770988C0BAD946E2,
    0x08E24FA074E5AB31,
    0x43DB5BFCE0FD108E,
    0x4B82D120A93AD2CA,
    0xFFFFFFFFFFFFFFFF,
];

const CST2: Natural = Natural::const_from(2);

use crate::generic::{
    CompressedDdhFeSecretKey, DdhFeCiphertext, DdhFeInstance, DdhFePublicKey, DdhFeSecretKey,
    MskItem,
};
use crate::traits::{FECipherText, FEInstance, FEPubKey, FESecretKey};

lazy_static::lazy_static! {
    static ref DH15_PRIME: Natural = Natural::from_limbs_desc(DH15_PRIME_LIMBS);
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

/*
    Type aliases (shared by both ec_fe.rs and ff_fe.rs)
*/
/// FE instance over Diffie Hellman group n°15 for arbitrary vector size.
pub type Instance<const N: usize> = DdhFeInstance<N, Natural, Natural>;
/// FE public over Diffie Hellman group n°15 for arbitrary vector size.
pub type PublicKey<const N: usize> = DdhFePublicKey<N, Natural>;
/// FE secret key over Diffie Hellman group n°15 for arbitrary vector size.
pub type SecretKey<const N: usize> = DdhFeSecretKey<N, Natural, Natural>;
/// FE compressed secret key over Diffie Hellman group n°15 for arbitrary vector size.
/// This is just the secret key when working over finite field, but it is implemented
/// to allow transparent usage when swaping to the elliptic curve based-fe of the crate.
pub type CompressedSecretKey = CompressedDdhFeSecretKey<Natural, Natural, Natural>;
/// FE ciphertext over Diffie Hellman group n°15 for arbitrary vector size.
pub type CipherText<const N: usize> = DdhFeCiphertext<N, Natural>;

/// Implementation of From and TryFrom to allow easy compression/decompression
/// between a CompressedSecretKey and a SecretKey. This has no effect in the case
/// of finite field based FE, but implemented for compatibility with Ristretto255
/// based FE of the crate.
impl<const N: usize> From<&SecretKey<N>> for CompressedSecretKey {
    fn from(value: &SecretKey<N>) -> CompressedSecretKey {
        CompressedSecretKey {
            g: value.g.clone(),
            sx: value.sx.clone(),
            tx: value.tx.clone(),
            x: value.x.to_vec(),
        }
    }
}

impl<const N: usize> TryFrom<&CompressedSecretKey> for SecretKey<N> {
    type Error = ();

    fn try_from(value: &CompressedSecretKey) -> Result<Self, Self::Error> {
        if value.x.len() == N {
            Ok(SecretKey {
                g: value.g.clone(),
                sx: value.sx.clone(),
                tx: value.tx.clone(),
                x: value.x.clone().try_into().unwrap(),
            })
        } else {
            Err(())
        }
    }
}

/*
    Implements traits defined in traits.rs
*/
impl<const N: usize> FEInstance<N, Natural, Natural> for Instance<N> {
    fn setup() -> Self {
        // PRNG
        let mut seeder = StdRng::try_from_rng(&mut SysRng).unwrap();
        let seed = Seed::from_bytes(array::from_fn(|_| seeder.random::<u8>()));
        let mut rng = random::uniform_random_natural_range(seed, CST2, DH15_PRIME.clone());

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

impl<const N: usize, T> FEPubKey<N, T, Natural, Natural> for PublicKey<N>
where
    Natural: From<T>,
    T: Copy,
{
    fn encrypt<R: CryptoRng + ?Sized>(&self, seeder: &mut R, vector: [T; N]) -> CipherText<N> {
        let seed = Seed::from_bytes(array::from_fn(|_| seeder.random::<u8>()));
        let mut rng = random::uniform_random_natural_range(seed, CST2, DH15_PRIME.clone());

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

    fn encrypt_mul<R: CryptoRng + ?Sized>(
        &self,
        seeder: &mut R,
        vector: [T; N],
        alpha: &Natural,
    ) -> CipherText<N> {
        let seed = Seed::from_bytes(array::from_fn(|_| seeder.random::<u8>()));
        let mut rng = random::uniform_random_natural_range(seed, CST2, DH15_PRIME.clone());

        let r = rng
            .next()
            .expect("Unable to generate a random value for encryption");

        let c = self.g.clone().mod_pow(&r, &*DH15_PRIME);
        let d = self.h.clone().mod_pow(&r, &*DH15_PRIME);

        let g_alpha = (&self.g).mod_pow(alpha, &*DH15_PRIME);

        let e: [Natural; N] = array::from_fn(|i| {
            (&g_alpha)
                .mod_pow(Natural::from(vector[i]), &*DH15_PRIME)
                .mod_mul(&self.mpk[i].clone().mod_pow(&r, &*DH15_PRIME), &*DH15_PRIME)
        });

        DdhFeCiphertext { c, d, e }
    }

    fn encrypt_mul_random<R: CryptoRng + ?Sized>(
        &self,
        seeder: &mut R,
        vector: [T; N],
    ) -> (CipherText<N>, Natural) {
        let seed = Seed::from_bytes(array::from_fn(|_| seeder.random::<u8>()));
        let mut rng = random::uniform_random_natural_range(seed, CST2, DH15_PRIME.clone());

        let alpha = rng
            .next()
            .expect("Unable to generate a random scalar for encryption");

        let ct = self.encrypt_mul(seeder, vector, &alpha);

        (ct, alpha)
    }
}

impl<const N: usize> FECipherText<Natural> for CipherText<N> {
    fn get_c(&self) -> Natural {
        self.c.clone()
    }
    fn get_d(&self) -> Natural {
        self.d.clone()
    }
    fn get_e(&self) -> &[Natural] {
        &self.e
    }
}

impl<const N: usize> FESecretKey<N, Natural, u16> for SecretKey<N> {
    fn decrypt(&self, ct: impl FECipherText<Natural>, bound: u16) -> Option<u16> {
        let ex = self.partial_decrypt(ct);

        let mut i = 0u16;
        let mut p = Natural::from(1u8);
        while i < bound && p != ex {
            i += 1;
            p.mod_mul_assign(&self.g, &*DH15_PRIME);
        }

        if i == bound { None } else { Some(i) }
    }

    fn partial_decrypt(&self, ct: impl FECipherText<Natural>) -> Natural {
        ct.get_e()
            .iter()
            .zip(self.x.clone())
            .fold(Natural::const_from(1), |acc, (ei, xi)| {
                acc.mod_mul(ei.mod_pow(xi, &*DH15_PRIME), &*DH15_PRIME)
            })
            .mod_mul(
                ct.get_c()
                    .mod_pow(&self.sx, &*DH15_PRIME)
                    .mod_mul(ct.get_d().mod_pow(&self.tx, &*DH15_PRIME), &*DH15_PRIME)
                    .mod_pow(&*DH15_PRIME - CST2, &*DH15_PRIME),
                &*DH15_PRIME,
            )
    }
}
