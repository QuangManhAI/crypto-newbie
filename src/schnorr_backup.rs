use crate::ecc::{mul_scalar, add_point_ecc, Point, EccParams};
use crate::sha256::sha256;

pub struct SchnorrKeyPair {
	pub private_key: u64,
	pub public_key: Point,
}

pub struct SchnorrSignature {
	pub e: u64,
	pub s: u64,
}
