// tai su dung sha256 tu file sha256.rs - khong can su dung thu vien hash ben ngoai
use crate::sha256::sha256;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Point {
	Infinity,
	Finite { x: u64, y: u64 },
}

pub struct Curve {
	pub p: u64,
	pub a: u64,
	pub b: u64,
	pub g: Point,
	pub n: u64,
}

fn mod_add(a: u64, b: u64, p: u64) -> u64 {
	((a as u128 + b as u128) % p as u128) as u64
}

fn mod_sub(a: u64, b: u64, p: u64) -> u64 {
	((a as i128 - b as i128).rem_euclid(p as i128)) as u64
}

fn mod_mul(a: u64, b: u64, p: u64) -> u64 {
	((a as u128 * b as u128) % p as u128) as u64
}

fn mod_inv(a: u64, p: u64) -> Option<u64> {
	if p == 0 {
		return None;
	}

	let mut t = 0i128;
	let mut new_t = 1i128;
	let mut r = p as i128;
	let mut new_r = (a % p) as i128;

	while new_r != 0 {
		let q = r / new_r;

		let old_t = t;
		t = new_t;
		new_t = old_t - q * new_t;

		let old_r = r;
		r = new_r;
		new_r = old_r - q * new_r;
	}

	if r != 1 {
		return None;
	}

	Some(t.rem_euclid(p as i128) as u64)
}

fn is_prime(n: u64) -> bool {
	if n < 2 {
		return false;
	}
	if n == 2 {
		return true;
	}
	if n % 2 == 0 {
		return false;
	}

	let mut d = 3u64;
	while d <= n / d {
		if n % d == 0 {
			return false;
		}
		d += 2;
	}

	true
}

fn next_prime(mut n: u64) -> u64 {
	if n <= 2 {
		return 2;
	}
	if n % 2 == 0 {
		n += 1;
	}

	while !is_prime(n) {
		n += 2;
	}
	n
}

fn parse_hex_u64_prefix(hex: &str, bytes: usize) -> u64 {
	let chars = bytes * 2;
	let clipped = &hex[..chars.min(hex.len())];
	u64::from_str_radix(clipped, 16).unwrap_or(0)
}

fn curve_seed(mssv: &str, full_name: &str, salt: &str) -> String {
	let input = format!("{}|{}|{}", mssv, full_name.to_uppercase(), salt);
	sha256(input.as_bytes())
}

fn has_valid_discriminant(a: u64, b: u64, p: u64) -> bool {
	let four_a3 = mod_mul(4, mod_mul(mod_mul(a, a, p), a, p), p);
	let twenty_seven_b2 = mod_mul(27, mod_mul(b, b, p), p);
	mod_add(four_a3, twenty_seven_b2, p) != 0
}

fn point_order(curve: &Curve, point: Point) -> u64 {
	if point == Point::Infinity {
		return 1;
	}

	let mut acc = point;
	let mut n = 1u64;
	let bound = curve.p + 1 + 2 * (curve.p as f64).sqrt() as u64 + 64;

	while n <= bound {
		acc = add_points(curve, acc, point);
		n += 1;
		if acc == Point::Infinity {
			return n;
		}
	}

	0
}

fn find_generator(curve: &Curve) -> Option<(Point, u64)> {
	for x in 0..curve.p {
		let x3 = mod_mul(mod_mul(x, x, curve.p), x, curve.p);
		let ax = mod_mul(curve.a, x, curve.p);
		let rhs = mod_add(mod_add(x3, ax, curve.p), curve.b, curve.p);

		for y in 0..curve.p {
			if mod_mul(y, y, curve.p) != rhs {
				continue;
			}

			let point = Point::Finite { x, y };
			let n = point_order(curve, point);
			if n > 50 {
				return Some((point, n));
			}
		}
	}

	None
}

pub fn is_on_curve(curve: &Curve, point: Point) -> bool {
	match point {
		Point::Infinity => true,
		Point::Finite { x, y } => {
			let lhs = mod_mul(y, y, curve.p);
			let x3 = mod_mul(mod_mul(x, x, curve.p), x, curve.p);
			let ax = mod_mul(curve.a, x, curve.p);
			let rhs = mod_add(mod_add(x3, ax, curve.p), curve.b, curve.p);
			lhs == rhs
		}
	}
}

pub fn add_points(curve: &Curve, p1: Point, p2: Point) -> Point {
	match (p1, p2) {
		(Point::Infinity, q) => q,
		(q, Point::Infinity) => q,
		(Point::Finite { x: x1, y: y1 }, Point::Finite { x: x2, y: y2 }) => {
			if x1 == x2 && mod_add(y1, y2, curve.p) == 0 {
				return Point::Infinity;
			}

			let lambda = if x1 == x2 && y1 == y2 {
				if y1 == 0 {
					return Point::Infinity;
				}
				let numerator = mod_add(mod_mul(3, mod_mul(x1, x1, curve.p), curve.p), curve.a, curve.p);
				let denominator = mod_mul(2, y1, curve.p);
				match mod_inv(denominator, curve.p) {
					Some(inv) => mod_mul(numerator, inv, curve.p),
					core::option::Option::None => return Point::Infinity,
				}
			} else {
				let numerator = mod_sub(y2, y1, curve.p);
				let denominator = mod_sub(x2, x1, curve.p);
				match mod_inv(denominator, curve.p) {
					Some(inv) => mod_mul(numerator, inv, curve.p),
					core::option::Option::None => return Point::Infinity,
				}
			};

			let x3 = mod_sub(mod_sub(mod_mul(lambda, lambda, curve.p), x1, curve.p), x2, curve.p);
			let y3 = mod_sub(mod_mul(lambda, mod_sub(x1, x3, curve.p), curve.p), y1, curve.p);

			Point::Finite { x: x3, y: y3 }
		}
	}
}

pub fn scalar_mul(curve: &Curve, k: u64, point: Point) -> Point {
	let mut result = Point::Infinity;
	let mut addend = point;
	let mut n = k;

	while n > 0 {
		if (n & 1) == 1 {
			result = add_points(curve, result, addend);
		}
		addend = add_points(curve, addend, addend);
		n >>= 1;
	}

	result
}

pub fn build_personal_curve(mssv: &str, full_name: &str) -> Result<Curve, String> {
	for attempt in 0..256u64 {
		let seed_p = curve_seed(mssv, full_name, &format!("p:{}", attempt));
		let seed_ab = curve_seed(mssv, full_name, &format!("ab:{}", attempt));

		let p_base = 2000 + (parse_hex_u64_prefix(&seed_p, 4) % 3000);
		let p = next_prime(p_base);

		let a = parse_hex_u64_prefix(&seed_ab[0..16], 4) % p;
		let b = parse_hex_u64_prefix(&seed_ab[16..32], 4) % p;

		if !has_valid_discriminant(a, b, p) {
			continue;
		}

		let mut curve = Curve {
			p,
			a,
			b,
			g: Point::Infinity,
			n: 0,
		};

		if let Some((g, n)) = find_generator(&curve) {
			curve.g = g;
			curve.n = n;
			return Ok(curve);
		}
	}

	Err("Khong tim duoc curve hop le tu seed MSSV + ho ten".to_string())
}

pub fn derive_private_key(curve: &Curve, mssv: &str, full_name: &str) -> u64 {
	let seed = curve_seed(mssv, full_name, "priv");
	let raw = parse_hex_u64_prefix(&seed, 8);

	let max_key = curve.n.saturating_sub(1).max(1);
	(raw % max_key) + 1
}

pub fn point_to_string(point: Point) -> String {
	match point {
		Point::Infinity => "O (Infinity)".to_string(),
		Point::Finite { x, y } => format!("({}, {})", x, y),
	}
}

pub fn demo_personal_curve(mssv: &str, full_name: &str) -> Result<String, String> {
	let curve = build_personal_curve(mssv, full_name)?;
	let d = derive_private_key(&curve, mssv, full_name);
	let q = scalar_mul(&curve, d, curve.g);

	if !is_on_curve(&curve, q) {
		return Err("Public key khong nam tren duong cong".to_string());
	}

	Ok(format!(
		"MSSV: {}\nHo ten: {}\nCurve: y^2 = x^3 + {}x + {} (mod {})\nG: {}\nOrder n: {}\nPrivate d: {}\nPublic Q = dG: {}",
		mssv,
		full_name,
		curve.a,
		curve.b,
		curve.p,
		point_to_string(curve.g),
		curve.n,
		d,
		point_to_string(q)
	))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn deterministic_curve_and_key() {
		let mssv = "22123456";
		let name = "Nguyen Van A";

		let c1 = build_personal_curve(mssv, name).unwrap();
		let c2 = build_personal_curve(mssv, name).unwrap();

		assert_eq!(c1.p, c2.p);
		assert_eq!(c1.a, c2.a);
		assert_eq!(c1.b, c2.b);
		assert_eq!(c1.g, c2.g);
		assert_eq!(c1.n, c2.n);

		let d1 = derive_private_key(&c1, mssv, name);
		let d2 = derive_private_key(&c2, mssv, name);
		assert_eq!(d1, d2);
	}

	#[test]
	fn generated_public_key_is_on_curve() {
		let curve = build_personal_curve("067206006852", "Nhu Pham Quang Manh").unwrap();
		let d = derive_private_key(&curve, "067206006852", "Nhu Pham Quang Manh");
		let q = scalar_mul(&curve, d, curve.g);

		assert!(q != Point::Infinity);
		assert!(is_on_curve(&curve, q));
	}
}
