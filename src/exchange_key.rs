use crate::ecc::{
	build_personal_curve, is_on_curve, point_to_string, scalar_mul, Curve, Point,
};
use crate::sha256::sha256;

pub struct PartyKeyPair {
	pub private_key: u64,
	pub public_key: Point,
}

fn parse_hex_u64_prefix(hex: &str, bytes: usize) -> u64 {
	let chars = bytes * 2;
	let clipped = &hex[..chars.min(hex.len())];
	u64::from_str_radix(clipped, 16).unwrap_or(0)
}

fn derive_party_private_key(curve: &Curve, mssv: &str, full_name: &str, role: &str) -> u64 {
	let seed_input = format!("{}|{}|{}", mssv, full_name.to_uppercase(), role);
	let digest = sha256(seed_input.as_bytes());
	let raw = parse_hex_u64_prefix(&digest, 8);

	// Private key must satisfy 1 <= d < n.
	let n_minus_1 = curve.n.saturating_sub(1).max(1);
	(raw % n_minus_1) + 1
}

fn generate_party_keypair(
	curve: &Curve,
	mssv: &str,
	full_name: &str,
	role: &str,
) -> Result<PartyKeyPair, String> {
	let d = derive_party_private_key(curve, mssv, full_name, role);
	let q = scalar_mul(curve, d, curve.g);

	if !is_on_curve(curve, q) || q == Point::Infinity {
		return Err(format!("Public key khong hop le cho vai tro {}", role));
	}

	Ok(PartyKeyPair {
		private_key: d,
		public_key: q,
	})
}

fn validate_public_key(curve: &Curve, q: Point) -> Result<(), String> {
	if q == Point::Infinity {
		return Err("Public key khong duoc la diem vo cuc".to_string());
	}

	if !is_on_curve(curve, q) {
		return Err("Public key khong nam tren duong cong".to_string());
	}

	Ok(())
}

fn derive_shared_secret(curve: &Curve, private_key: u64, peer_public_key: Point) -> Result<Point, String> {
	validate_public_key(curve, peer_public_key)?;

	let shared = scalar_mul(curve, private_key, peer_public_key);
	if shared == Point::Infinity {
		return Err("Shared secret khong hop le (Infinity)".to_string());
	}

	Ok(shared)
}

fn derive_session_key(shared_secret: Point) -> Result<String, String> {
	match shared_secret {
		Point::Infinity => Err("Khong the tao session key tu Infinity".to_string()),
		Point::Finite { x, y } => {
			let material = format!("{}|{}", x, y);
			Ok(sha256(material.as_bytes()))
		}
	}
}

pub fn demo_ecdh_exchange(mssv: &str, full_name: &str) -> Result<String, String> {
	let curve = build_personal_curve(mssv, full_name)?;

	let alice = generate_party_keypair(&curve, mssv, full_name, "alice")?;
	let bob = generate_party_keypair(&curve, mssv, full_name, "bob")?;

	let shared_alice = derive_shared_secret(&curve, alice.private_key, bob.public_key)?;
	let shared_bob = derive_shared_secret(&curve, bob.private_key, alice.public_key)?;

	if shared_alice != shared_bob {
		return Err("ECDH loi: hai ben khong ra cung shared secret".to_string());
	}

	let session_key = derive_session_key(shared_alice)?;

	let report = format!(
		"[ECDH Exchange]\nCurve: y^2 = x^3 + {}x + {} (mod {})\nG: {}\nOrder n: {}\n\nAlice dA: {}\nAlice QA: {}\n\nBob dB: {}\nBob QB: {}\n\nShared S: {}\nSession key (SHA-256): {}",
		curve.a,
		curve.b,
		curve.p,
		point_to_string(curve.g),
		curve.n,
		alice.private_key,
		point_to_string(alice.public_key),
		bob.private_key,
		point_to_string(bob.public_key),
		point_to_string(shared_alice),
		session_key
	);

	Ok(report)
}

#[cfg(test)]
mod tests {
	use super::demo_ecdh_exchange;

	#[test]
	fn ecdh_exchange_runs() {
		let output = demo_ecdh_exchange("067206006852", "Nhu Pham Quang Manh").unwrap();
		assert!(output.contains("Session key (SHA-256):"));
	}
}
