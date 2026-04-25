use crate::sha256::sha256;

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

impl Copy for Point {}

impl Clone for Point {
	fn clone(&self) -> Self {
		*self
	}
}

impl PartialEq for Point {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Point::Infinity, Point::Infinity) => true,
			(Point::Finite { x: x1, y: y1 }, Point::Finite { x: x2, y: y2 }) => {
				x1 == x2 && y1 == y2
			}
			_ => false,
		}
	}
}

impl Eq for Point {}

impl core::fmt::Debug for Point {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Point::Infinity => write!(f, "Infinity"),
			Point::Finite { x, y } => write!(f, "Finite({}, {})", x, y),
		}
	}
}

fn mod_add(a: u64, b: u64, p: u64) -> u64 {
	((a % p) + (b % p)) % p
}

fn mod_sub(a: u64, b: u64, p: u64) -> u64 {
	((a as i128 - b as i128).rem_euclid(p as i128)) as u64
}

fn mod_mul(a: u64, b: u64, p: u64) -> u64 {
	((a as u128 * b as u128) % p as u128) as u64
}

fn mod_inv(a: u64, p: u64) -> Option<u64> {
	let mut t = 0i128;
	let mut new_t = 1i128;
	let mut r = p as i128;
	let mut new_r = (a % p) as i128;

	while new_r != 0 {
		let q = r / new_r;

		let temp_t = t - q * new_t;
		t = new_t;
		new_t = temp_t;

		let temp_r = r - q * new_r;
		r = new_r;
		new_r = temp_r;
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
	while d * d <= n {
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

fn order_of_point(curve: &Curve, point: Point) -> u64 {
	if point == Point::Infinity {
		return 1;
	}

	let mut q = point;
	let mut n = 1u64;
	let bound = curve.p + 1 + 2 * (curve.p as f64).sqrt() as u64 + 50;

	while n <= bound {
		q = add_points(curve, q, point);
		n += 1;
		if q == Point::Infinity {
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
			if mod_mul(y, y, curve.p) == rhs {
				let point = Point::Finite { x, y };
				let n = order_of_point(curve, point);
				if n > 50 {
					return Some((point, n));
				}
			}
		}
	}
	None
}

pub fn is_on_curve(curve: &Curve, p: Point) -> bool {
	match p {
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
				let num = mod_add(mod_mul(3, mod_mul(x1, x1, curve.p), curve.p), curve.a, curve.p);
				let den = mod_mul(2, y1, curve.p);
				match mod_inv(den, curve.p) {
					Some(inv) => mod_mul(num, inv, curve.p),
					None => return Point::Infinity,
				}
			} else {
				let num = mod_sub(y2, y1, curve.p);
				let den = mod_sub(x2, x1, curve.p);
				match mod_inv(den, curve.p) {
					Some(inv) => mod_mul(num, inv, curve.p),
					None => return Point::Infinity,
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
		if n & 1 == 1 {
			result = add_points(curve, result, addend);
		}
		addend = add_points(curve, addend, addend);
		n >>= 1;
	}

	result
}

pub fn build_personal_curve(mssv: &str, full_name: &str) -> Result<Curve, String> {
	for attempt in 0..128u64 {
		let seed_p = curve_seed(mssv, full_name, &format!("p:{}", attempt));
		let seed_ab = curve_seed(mssv, full_name, &format!("ab:{}", attempt));

		let p_base = 2000 + (parse_hex_u64_prefix(&seed_p, 4) % 3000);
		let p = next_prime(p_base);

		let a = parse_hex_u64_prefix(&seed_ab[0..16], 4) % p;
		let b = parse_hex_u64_prefix(&seed_ab[16..32], 4) % p;

		let discriminant = mod_add(
			mod_mul(4, mod_mul(mod_mul(a, a, p), a, p), p),
			mod_mul(27, mod_mul(b, b, p), p),
			p,
		);

		if discriminant == 0 {
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
	((raw % (curve.n.saturating_sub(1).max(1))) + 1).min(curve.n.saturating_sub(1).max(1))
}

pub fn point_to_string(p: Point) -> String {
	match p {
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

	let output = format!(
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
	);

	Ok(output)
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
}
