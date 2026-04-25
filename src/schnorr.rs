use crate::ecc::{
	add_points, build_personal_curve, derive_private_key, is_on_curve, point_to_string, scalar_mul,
	Curve, Point,
};
use crate::sha256::sha256;

pub struct SchnorrKeyPair {
	pub private_key: u64,
	pub public_key: Point,
}

pub struct SchnorrSignature {
	pub e: u64,
	pub s: u64,
}

fn mod_n_add(a: u64, b: u64, n: u64) -> u64 {
	if n == 0 {
		return 0;
	}
	((a as u128 + b as u128) % n as u128) as u64
}

fn mod_n_mul(a: u64, b: u64, n: u64) -> u64 {
	if n == 0 {
		return 0;
	}
	((a as u128 * b as u128) % n as u128) as u64
}

fn parse_hex_u64_prefix(hex: &str, bytes: usize) -> u64 {
	let chars = bytes * 2;
	let clipped = &hex[..chars.min(hex.len())];
	u64::from_str_radix(clipped, 16).unwrap_or(0)
}

fn point_xy(point: Point) -> Result<(u64, u64), String> {
	match point {
		Point::Finite { x, y } => Ok((x, y)),
		Point::Infinity => Err("Diem vo cuc khong hop le cho Schnorr".to_string()),
	}
}

fn hash_to_scalar(input: &str, n: u64) -> u64 {
	if n <= 1 {
		return 0;
	}
	let digest = sha256(input.as_bytes());
	parse_hex_u64_prefix(&digest, 8) % n
}

fn challenge_scalar(r: Point, public_key: Point, message: &[u8], n: u64) -> Result<u64, String> {
	let (rx, ry) = point_xy(r)?;
	let (px, py) = point_xy(public_key)?;
	let msg = String::from_utf8_lossy(message);
	let material = format!("{}|{}|{}|{}|{}", rx, ry, px, py, msg);

	Ok(hash_to_scalar(&material, n))
}

fn deterministic_nonce(curve: &Curve, private_key: u64, message: &[u8]) -> u64 {
	let msg = String::from_utf8_lossy(message);
	let material = format!("SCHNORR_NONCE|{}|{}", private_key, msg);
	let mut k = hash_to_scalar(&material, curve.n);

	if curve.n > 1 && k == 0 {
		k = 1;
	}

	k
}

pub fn schnorr_keygen(mssv: &str, full_name: &str) -> Result<(Curve, SchnorrKeyPair), String> {
	let curve = build_personal_curve(mssv, full_name)?;
	let d = derive_private_key(&curve, mssv, full_name);
	let p = scalar_mul(&curve, d, curve.g);

	if !is_on_curve(&curve, p) || p == Point::Infinity {
		return Err("Public key Schnorr khong hop le".to_string());
	}

	Ok((
		curve,
		SchnorrKeyPair {
			private_key: d,
			public_key: p,
		},
	))
}

pub fn schnorr_sign(curve: &Curve, private_key: u64, public_key: Point, message: &[u8]) -> Result<SchnorrSignature, String> {
	if curve.n <= 1 {
		return Err("Order n khong hop le cho Schnorr".to_string());
	}

	let k = deterministic_nonce(curve, private_key, message);
	if k == 0 {
		return Err("Nonce k = 0, khong hop le".to_string());
	}

	let r = scalar_mul(curve, k, curve.g);
	let e = challenge_scalar(r, public_key, message, curve.n)?;
	let s = mod_n_add(k, mod_n_mul(e, private_key, curve.n), curve.n);

	Ok(SchnorrSignature { e, s })
}

pub fn schnorr_verify(curve: &Curve, public_key: Point, message: &[u8], sig: &SchnorrSignature) -> bool {
	if curve.n <= 1 {
		return false;
	}

	if public_key == Point::Infinity || !is_on_curve(curve, public_key) {
		return false;
	}

	if sig.e >= curve.n || sig.s >= curve.n {
		return false;
	}

	// R' = sG - eP = sG + (n - e)P
	let s_g = scalar_mul(curve, sig.s, curve.g);
	let neg_e_p = scalar_mul(curve, (curve.n - (sig.e % curve.n)) % curve.n, public_key);
	let r_prime = add_points(curve, s_g, neg_e_p);

	let e_prime = match challenge_scalar(r_prime, public_key, message, curve.n) {
		Ok(v) => v,
		Err(_) => return false,
	};

	e_prime == sig.e
}

pub fn demo_schnorr(mssv: &str, full_name: &str, message: &str) -> Result<String, String> {
	let (curve, keypair) = schnorr_keygen(mssv, full_name)?;
	let signature = schnorr_sign(&curve, keypair.private_key, keypair.public_key, message.as_bytes())?;
	let verified = schnorr_verify(&curve, keypair.public_key, message.as_bytes(), &signature);

	let report = format!(
		"[Schnorr Signature]\nCurve: y^2 = x^3 + {}x + {} (mod {})\nG: {}\nOrder n: {}\n\nPrivate d: {}\nPublic P: {}\nMessage: {}\nSignature (e, s): ({}, {})\nVerify: {}",
		curve.a,
		curve.b,
		curve.p,
		point_to_string(curve.g),
		curve.n,
		keypair.private_key,
		point_to_string(keypair.public_key),
		message,
		signature.e,
		signature.s,
		verified
	);

	Ok(report)
}

#[cfg(test)]
mod tests {
	use super::{schnorr_keygen, schnorr_sign, schnorr_verify};

	#[test]
	fn schnorr_sign_verify_ok() {
		let (curve, keypair) = schnorr_keygen("067206006852", "Nhu Pham Quang Manh").unwrap();
		let msg = b"hello schnorr";

		let sig = schnorr_sign(&curve, keypair.private_key, keypair.public_key, msg).unwrap();
		assert!(schnorr_verify(&curve, keypair.public_key, msg, &sig));
	}

	#[test]
	fn schnorr_rejects_modified_message() {
		let (curve, keypair) = schnorr_keygen("067206006852", "Nhu Pham Quang Manh").unwrap();
		let sig = schnorr_sign(&curve, keypair.private_key, keypair.public_key, b"msg A").unwrap();

		assert!(!schnorr_verify(&curve, keypair.public_key, b"msg B", &sig));
	}
}
