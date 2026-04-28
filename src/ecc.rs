// (a+b) mod p
fn add_mod_p(a: u64, b: u64, p:u64) -> u64 {
	((a as u128+ b as u128) % p as u128) as u64
}

// (a * b) mod p
fn mul_mod_p(a: u64, b: u64, p: u64) -> u64 {
	((a as u128* b as u128) % p as u128) as u64
}

// (a - b) mod p
fn sub_mod_p(a: u64, b: u64, p: u64) -> u64 {
	((a as i128 - b as i128).rem_euclid(p as i128)) as u64
}

fn euclid_inv_mod_p(a: u64, p: u64) -> Option<u64> {
	if p == 0 {return None};

	let mut temp = 0i128;
	let mut new_temp = 1i128;
	let mut r = p as i128;
	let mut r_new = (a % p) as i128;

	while r_new != 0 {
		let q = r / r_new;

		let old_temp = temp;
		temp = new_temp;
		new_temp = old_temp - q * new_temp;

		let old_r = r;
		r = r_new;
		r_new = old_r - q * r_new;
	}

	if r > 1 {return None};

	if temp < 0 {
		Some((temp + p as i128) as u64)
	} else {
		Some(temp as u64)
	}
}

use crate::sha256::sha256;
pub fn seed_gen_from_name_mssv(name: &str, mssv: &str, salt: &str) -> u64 {
	let input = format!("{}|{}|{}", name.to_uppercase(), mssv, salt);
	let hash_hex = sha256(input.as_bytes());

	u64::from_str_radix(&hash_hex[..12], 16).unwrap_or(0)
}

use crate::sha256::is_prime;
fn next_prime(mut n: u64) -> u64 {
	if n % 2 == 0 {n += 1}
	while !is_prime(n as u32) {
		n += 2;
	}
	n
}

pub struct EccParams {
	pub p: u64,
	pub a: u64,
	pub b: u64,
}

impl Copy for EccParams {}
impl Clone for EccParams {
	fn clone(&self) -> Self {
		*self
	}
}

fn build_ecc_params(name: &str, mssv: &str) -> EccParams {
	let p_base = 5000 + (seed_gen_from_name_mssv(name, mssv, "prime_base") % 5000);
	let p = next_prime(p_base);

	let mut salt_counter = 0;

	loop {
		let a = seed_gen_from_name_mssv(name, mssv, &format!("a:{}", salt_counter)) % p;
		let b = seed_gen_from_name_mssv(name, mssv, &format!("b:{}", salt_counter)) % p;

		let a3 = mul_mod_p(a, mul_mod_p(a, a, p), p);
		let b2 = mul_mod_p(b, b, p);

		let delta = add_mod_p(mul_mod_p(4, a3, p), mul_mod_p(27, b2, p), p);

		if delta != 0 {
			return EccParams{p, a, b};
		}

		salt_counter += 1;
	}
}

pub enum Point {
	Infinity,
	Finite {x: u64, y: u64},
}

impl PartialEq for Point{
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Point::Infinity, Point::Infinity) => true,

			(Point::Finite { x: x1, y: y1 }, Point::Finite { x: x2, y: y2 }) => {
				x1 == x2 && y1 == y2
			}

			_=> false,
		}
	}
}

impl Eq for Point {
	
}

impl Clone for Point {
	fn clone(&self) -> Self {
		match self {
			Point::Infinity => Point::Infinity,
			Point::Finite { x, y } => Point::Finite { 
				x: *x, y: *y 
			},
		}
	}
}

impl Copy for Point {
	
}

impl Point {
	#[allow(dead_code)]
	pub fn print_point(&self) {
		match self {
			Point::Infinity => println!("Point: Infinity"),
			Point::Finite { x, y } => println!("Point: ({}, {})", x, y),
		}
	}
}

pub fn add_point_ecc(p1: Point, p2: Point, params: EccParams) -> Point{
	let p = params.p;

	match (p1, p2) {
		(Point::Infinity, any) => any,
		(any, Point::Infinity) => any,

		(Point::Finite { x: x1, y: y1 }, Point::Finite { x: x2, y: y2 }) => {
			if x1 == x2 && add_mod_p(y1, y2, p) == 0 {
				return Point::Infinity;
			}

			let lambda = if x1 == x2 && y1 == y2 {
				let num = add_mod_p(mul_mod_p(3, mul_mod_p(x1, x1, p), p), params.a, p);
				let den = mul_mod_p(2, y1, p);

				match euclid_inv_mod_p(den, p) {
					Some(inv) => mul_mod_p(num, inv, p),
					Option::None => return Point::Infinity,
				}
			} else {
				let num = sub_mod_p(y2, y1, p);
				let den = sub_mod_p(x2, x1, p);

				match euclid_inv_mod_p(den, p) {
					Some(inv) => mul_mod_p(num, inv, p),
					Option::None => return Point::Infinity,
				}
			};

			let x3 = sub_mod_p(sub_mod_p(mul_mod_p(lambda, lambda, p), x1, p), x2, p);
			let y3 = sub_mod_p(mul_mod_p(lambda, sub_mod_p(x1, x3, p), p), y1, p);

			Point::Finite { x: x3, y: y3 }
		}
	}
} 

pub fn mul_scalar(mut k: u64, point: Point, params: EccParams) -> Point {
	let mut result = Point::Infinity;
	let mut added = point;

	while k > 0 {
		if (k & 1) == 1 {
			result = add_point_ecc(result, added, params);
		}
		added = add_point_ecc(added, added, params);

		k >>= 1 ;
	}

	result
}

fn find_g (params: EccParams) -> Option<Point> {
	for x in 0..params.p {
		let x3 = mul_mod_p(x, mul_mod_p(x, x, params.p), params.p);
		let ax = mul_mod_p(params.a, x, params.p);
		let rhs = add_mod_p(add_mod_p(x3, ax, params.p), params.b, params.p);

		for y in 0..params.p {
			if mul_mod_p(y, y, params.p) == rhs {
				return Some(Point::Finite { x, y });
			}
		}
	}
	None
}

#[allow(dead_code)]
pub fn run_identity_ecc_demo() {
    let name = "Nhu Pham Quang Manh";
    let mssv = "067206006852";

    let params = build_ecc_params(name, mssv);
    let g = find_g(params).expect("Khong tim thay diem G!");

    println!("Duong cong cua: {}", name.to_uppercase());
    println!("y^2 = x^3 + {}x + {} (mod {})", params.a, params.b, params.p);
	print!("gen G: ");
	g.print_point();


    let priv_a = 2026; 
    let pub_a = mul_scalar(priv_a, g, params);

    let priv_b = 1004; 
    let pub_b = mul_scalar(priv_b, g, params);

    let shared_secret_a = mul_scalar(priv_a, pub_b, params);
    let shared_secret_b = mul_scalar(priv_b, pub_a, params);

    println!("\nresult of ecc demo:");
	print!("Public Key A: ");
	pub_a.print_point();
	print!("Public Key B: ");
	pub_b.print_point();
	print!("Shared Secret A: ");
	shared_secret_a.print_point();
	print!("Shared Secret B: ");
	shared_secret_b.print_point();

    if shared_secret_a == shared_secret_b {
        println!("\nSuccess we are have ecc to exchange keys!");
    }
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_add_mod_p() {
		assert_eq!(add_mod_p(5, 7, 11), 1);
		assert_eq!(add_mod_p(10, 10, 17), 3);
		assert_eq!(add_mod_p(0, 100, 101), 100);
	}

	#[test]
	fn test_mul_mod_p() {
		assert_eq!(mul_mod_p(3, 4, 11), 1);
		assert_eq!(mul_mod_p(5, 5, 23), 2);
		assert_eq!(mul_mod_p(0, 999, 7), 0);
	}

	#[test]
	fn test_sub_mod_p() {
		assert_eq!(sub_mod_p(10, 3, 11), 7);
		assert_eq!(sub_mod_p(3, 10, 11), 4);
		assert_eq!(sub_mod_p(0, 1, 11), 10);
	}

	#[test]
	fn test_euclid_inv_mod_p() {
		assert_eq!(euclid_inv_mod_p(3, 11), Some(4));
		assert_eq!(euclid_inv_mod_p(2, 11), Some(6));
		assert_eq!(euclid_inv_mod_p(0, 11), None);
		assert_eq!(euclid_inv_mod_p(2, 4), None);
	}

	#[test]
	fn test_next_prime() {
		assert!(is_prime(next_prime(100) as u32));
		assert!(is_prime(next_prime(50) as u32));
		assert!(is_prime(next_prime(1000) as u32));
	}

	#[test]
	fn test_point_equality() {
		let p1 = Point::Infinity;
		let p2 = Point::Infinity;
		assert!(p1 == p2);

		let p3 = Point::Finite { x: 5, y: 7 };
		let p4 = Point::Finite { x: 5, y: 7 };
		assert!(p3 == p4);

		let p5 = Point::Finite { x: 5, y: 8 };
		assert!(p3 != p5);
	}

	#[test]
	fn test_point_clone_copy() {
		let p = Point::Finite { x: 10, y: 20 };
		let p_clone = p.clone();
		let p_copy = p;

		assert!(p == p_clone);
		assert!(p == p_copy);
	}

	#[test]
	fn test_point_addition_with_infinity() {
		let p = EccParams { p: 23, a: 1, b: 1 };
		let point = Point::Finite { x: 5, y: 7 };
		let infinity = Point::Infinity;

		let result1 = add_point_ecc(point, infinity, p);
		let result2 = add_point_ecc(infinity, point, p);

		assert!(result1 == point);
		assert!(result2 == point);
	}

	#[test]
	fn test_scalar_multiplication_basic() {
		let p = EccParams { p: 23, a: 1, b: 1 };
		let point = Point::Finite { x: 5, y: 7 };

		let result0 = mul_scalar(0, point, p);
		assert!(result0 == Point::Infinity);

		let result1 = mul_scalar(1, point, p);
		assert!(result1 == point);

		let result2 = mul_scalar(2, point, p);
		let manual_add = add_point_ecc(point, point, p);
		assert!(result2 == manual_add);
	}

	#[test]
	fn test_ecc_key_exchange() {
		let name = "Test";
		let mssv = "123456";
		let params = build_ecc_params(name, mssv);

		if let Some(g) = find_g(params) {
			let priv_a: u64 = 1234;
			let priv_b: u64 = 5678;

			let pub_a = mul_scalar(priv_a, g, params);
			let pub_b = mul_scalar(priv_b, g, params);

			let shared_a = mul_scalar(priv_a, pub_b, params);
			let shared_b = mul_scalar(priv_b, pub_a, params);

			assert!(shared_a == shared_b);
		}
	}

	#[test]
	fn test_seed_generation() {
		let seed1 = seed_gen_from_name_mssv("Alice", "001", "salt1");
		let seed2 = seed_gen_from_name_mssv("Alice", "001", "salt1");
		let seed3 = seed_gen_from_name_mssv("Alice", "001", "salt2");

		assert_eq!(seed1, seed2);
		assert_ne!(seed1, seed3);
	}

	#[test]
	fn test_ecc_params_build() {
		let params = build_ecc_params("User1", "067206006852");

		assert!(params.p > 5000);
		assert!(is_prime(params.p as u32));
		assert!(params.a < params.p);
		assert!(params.b < params.p);
	}
}