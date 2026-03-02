use rand::{
    CryptoRng, SeedableRng,
    rngs::{StdRng, SysRng},
};

pub(crate) fn random_coefficient<R: CryptoRng + ?Sized>(rng: &mut R, size: usize) -> u8 {
	let mut r = vec![0u8; size];
	rng.fill_bytes(&mut r);

	r.iter().map(|b| b.count_ones() as u8).sum()
}