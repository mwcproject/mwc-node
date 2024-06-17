#![allow(non_snake_case)]

use crate::blake2::blake2b::Blake2b;
use crate::types::Error;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::secp::Secp256k1;

/// A stealth address containing the pair of public keys (A=aG, B=bG)
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct StealthAddress {
	pub A: PublicKey,
	pub B: PublicKey,
}

impl StealthAddress {
	pub fn calc_shared_secrets(
		&self,
		secp: &Secp256k1,
		r: &SecretKey,
	) -> Result<(SecretKey, SecretKey), Error> {
		let mut rA = self.A;
		rA.mul_assign(secp, &r)?;

		let mut hasher = Blake2b::new(32);
		hasher.update(&b"k"[..]);
		hasher.update(&rA.serialize_vec(true));
		hasher.update(&self.A.serialize_vec(true));
		hasher.update(&self.B.serialize_vec(true));
		let k = hasher.finalize();

		let mut hasher = Blake2b::new(32);
		hasher.update(&b"q"[..]);
		hasher.update(&rA.serialize_vec(true));
		hasher.update(&self.A.serialize_vec(true));
		hasher.update(&self.B.serialize_vec(true));
		let q = hasher.finalize();

		Ok((
			SecretKey::from_slice(k.as_bytes())?,
			SecretKey::from_slice(q.as_bytes())?,
		))
	}
}

/// A view key containing the secret key a and public key B=bG
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ViewKey {
	pub a: SecretKey,
	pub B: PublicKey,
}

/// A spend key containing the pair of secret keys (a,b)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpendKey {
	pub a: SecretKey,
	pub b: SecretKey,
}
