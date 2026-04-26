fn big_sigma_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn big_sigma_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn small_sigma_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn small_sigma_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn is_prime(n: u32) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }

    let mut i = 3u32;
    while i * i <= n {
        if n % i == 0 {
            return false;
        }
        i += 2;
    }

    true
}

fn get_n_primes(n: usize) -> Vec<u32> {
    let mut primes = Vec::with_capacity(n);
    let mut candidate = 2u32;

    while primes.len() < n {
        if is_prime(candidate) {
            primes.push(candidate);
        }
        candidate += 1;
    }
    primes
}

fn compute_initial_hash() -> [u32; 8] {
    let primes = get_n_primes(8);
    let mut h = [0u32; 8];

    for i in 0..8 {
        let sqrt = (primes[i] as f64).sqrt();
        let fractional_part = sqrt - sqrt.floor();
        h[i] = (fractional_part * (2f64.powi(32))) as u32;
    }

    h
}

fn compute_k_constants() -> [u32; 64] {
    let primes = get_n_primes(64);
    let mut k = [0u32; 64];

    for i in 0..64 {
        let cbrt = (primes[i] as f64).cbrt();
        let fractional_part = cbrt - cbrt.floor();
        k[i] = (fractional_part * (2f64.powi(32))) as u32;
    }

    k
}

fn pad_message(message: &[u8]) -> Vec<u8> {
    let mut padded = message.to_vec();

    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }

    padded
}

fn append_length(mut padded_message: Vec<u8>, original_bit_len: u64) -> Vec<u8> {
    padded_message.extend_from_slice(&original_bit_len.to_be_bytes());
    padded_message
}

fn parse_into_blocks(full_padded_message: &[u8]) -> Vec<[u32; 16]> {
    full_padded_message
        .chunks_exact(64)
        .map(|chunk| {
            let mut block = [0u32; 16];
            for (i, word) in block.iter_mut().enumerate() {
                let start = i * 4;
                *word = u32::from_be_bytes([
                    chunk[start],
                    chunk[start + 1],
                    chunk[start + 2],
                    chunk[start + 3],
                ]);
            }
            block
        })
        .collect()
}

fn preprocess(message: &[u8]) -> Vec<[u32; 16]> {
    let original_bit_len = (message.len() as u64) * 8;
    let padded = pad_message(message);
    let complete_message = append_length(padded, original_bit_len);
    parse_into_blocks(&complete_message)
}

fn extend_message_schedule(m_block: &[u32; 16]) -> [u32; 64] {
    let mut w = [0u32; 64];

    w[..16].copy_from_slice(m_block);

    for t in 16..64 {
        w[t] = small_sigma_1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma_0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }

    w
}

fn compress_block(w: &[u32; 64], k: &[u32; 64], h_current: &mut [u32; 8]) {
    let mut a = h_current[0];
    let mut b = h_current[1];
    let mut c = h_current[2];
    let mut d = h_current[3];
    let mut e = h_current[4];
    let mut f = h_current[5];
    let mut g = h_current[6];
    let mut h = h_current[7];

    for t in 0..64 {
        let t1 = h
            .wrapping_add(big_sigma_1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(k[t])
            .wrapping_add(w[t]);

        let t2 = big_sigma_0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    h_current[0] = h_current[0].wrapping_add(a);
    h_current[1] = h_current[1].wrapping_add(b);
    h_current[2] = h_current[2].wrapping_add(c);
    h_current[3] = h_current[3].wrapping_add(d);
    h_current[4] = h_current[4].wrapping_add(e);
    h_current[5] = h_current[5].wrapping_add(f);
    h_current[6] = h_current[6].wrapping_add(g);
    h_current[7] = h_current[7].wrapping_add(h);
}

pub fn sha256(message: &[u8]) -> String {
    let h_init = compute_initial_hash();
    let k_constants = compute_k_constants();
    let preprocessed = preprocess(message);

    let mut h_current = h_init;

    for block in preprocessed {
        let w = extend_message_schedule(&block);
        compress_block(&w, &k_constants, &mut h_current);
    }

    h_current.iter().map(|x| format!("{:08x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::sha256;

    #[test]
    fn hash_abc_matches_standard_vector() {
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
