use crate::ecc::{EccParams, Point, mul_scalar, seed_gen_from_name_mssv};

struct Schnorr {
	r_point: Point,
	s_value: u64,
}

impl Schnorr {
	fn sign(mess: &str, priv_key: u64, params: EccParams, n: u64, g: Point) -> Self {
		let k = seed_gen_from_name_mssv(mess, "nonce_k", "salt") % n;

		let r_point = mul_scalar(k, g, params);

		let pub_key = mul_scalar(priv_key, g, params);

		let e_input = match (r_point, pub_key) {
					(Point::Finite { x: rx, .. }, Point::Finite { x: px, .. }) => {
						format!("{}{}{}", rx, px, message)
					},
					_ => message.to_string(),
				};
				let e = hash_to_u64(&sha256(e_input.as_bytes()), n);

				let ex = ((e as u128 * priv_key as u128) % n as u128) as u64;
				let s_value = ((k as u128 + ex as u128) % n as u128) as u64;
				
				SchnorrSignature { r_point, s_value }
	}

pub fn verify(&self, message: &str, pub_key: Point, params: &CurveParams, n: u64, g: Point) -> bool {
        let e_input = match (self.r_point, pub_key) {
            (Point::Finite { x: rx, .. }, Point::Finite { x: px, .. }) => {
                format!("{}{}{}", rx, px, message)
            },
            _ => message.to_string(),
        };
        let e = hash_to_u64(&sha256(e_input.as_bytes()), n);
        
        let lhs = scalar_mul(self.s_value, g, params);
        
        let ep = scalar_mul(e, pub_key, params);
        let rhs = add_points(self.r_point, ep, params);

        lhs == rhs
    }
}