mod aes;
mod sha256;
mod ecc;
mod schnorr;

use std::time::{Duration, Instant};

fn print_perf_row(name: &str, total: Duration, runs: u32) {
    let total_ms = total.as_secs_f64() * 1_000.0;
    let avg_us = (total.as_secs_f64() * 1_000_000.0) / runs as f64;
    println!(
        "{:<26} total: {:>10.3} ms | avg: {:>10.3} us | runs: {}",
        name, total_ms, avg_us, runs
    );
}

fn main() {
    println!("================ CHUONG TRINH DEMO HE THONG MAT MA ================");

    let aes_key = "Nhu Pham Quang Manh";
    let plaintext = "Truong Dai hoc Giao Thong Van Tai TPHCM";
    let mssv = "067206006852";
    let full_name = "Nhu Pham Quang Manh";
    let schnorr_message = "Schnorr demo message";

    println!("\n[1] DEMO HE THONG");

    println!("\n--- AES-128 Demo ---");
    let cipher_states = aes::aes_128_encrypt(plaintext, aes_key);
    println!("Key: {}", aes_key);
    println!("Plaintext: {}", plaintext);
    println!("Cipher blocks:");
    aes::print_hex_states(&cipher_states);

    let decrypted = aes::aes_128_decrypt(cipher_states, aes_key);
    println!("Decrypted: {}", decrypted);

    let message = plaintext;
    let digest = sha256::sha256(message.as_bytes());

    println!("\n--- SHA-256 Demo ---");
    println!("Input: {}", message);
    println!("SHA-256: {}", digest);

    println!("\n--- ECC Personal Curve Demo ---");
    match ecc::demo_personal_curve(mssv, full_name) {
        Ok(report) => println!("{}", report),
        Err(err) => println!("Loi tao curve: {}", err),
    }

    println!("\n--- Schnorr Signature Demo ---");
    match schnorr::demo_schnorr(mssv, full_name, schnorr_message) {
        Ok(report) => println!("{}", report),
        Err(err) => println!("Loi Schnorr: {}", err),
    }

    println!("\n[2] DANH GIA HIEU NANG");
    println!("Thong so: key='{}', plaintext='{}'", aes_key, plaintext);

    let perf_plaintext = plaintext.repeat(8);

    let aes_runs = 500u32;
    let aes_start = Instant::now();
    for _ in 0..aes_runs {
        let c = aes::aes_128_encrypt(&perf_plaintext, aes_key);
        let p = aes::aes_128_decrypt(c, aes_key);
        if p != perf_plaintext {
            println!("AES benchmark loi: decrypt khong khop plaintext");
            return;
        }
    }
    let aes_total = aes_start.elapsed();

    let sha_runs = 20_000u32;
    let sha_start = Instant::now();
    let mut last_digest = String::new();
    for _ in 0..sha_runs {
        last_digest = sha256::sha256(perf_plaintext.as_bytes());
    }
    let sha_total = sha_start.elapsed();

    let ecc_runs = 400u32;
    let ecc_start = Instant::now();
    for _ in 0..ecc_runs {
        let curve = match ecc::build_personal_curve(mssv, full_name) {
            Ok(c) => c,
            Err(err) => {
                println!("ECC benchmark loi tao curve: {}", err);
                return;
            }
        };
        let d = ecc::derive_private_key(&curve, mssv, full_name);
        let q = ecc::scalar_mul(&curve, d, curve.g);
        if !ecc::is_on_curve(&curve, q) {
            println!("ECC benchmark loi: Q khong nam tren duong cong");
            return;
        }
    }
    let ecc_total = ecc_start.elapsed();

    let schnorr_runs = 500u32;
    let schnorr_start = Instant::now();
    for _ in 0..schnorr_runs {
        let (curve, keypair) = match schnorr::schnorr_keygen(mssv, full_name) {
            Ok(v) => v,
            Err(err) => {
                println!("Schnorr benchmark loi keygen: {}", err);
                return;
            }
        };
        let sig = match schnorr::schnorr_sign(
            &curve,
            keypair.private_key,
            keypair.public_key,
            schnorr_message.as_bytes(),
        ) {
            Ok(s) => s,
            Err(err) => {
                println!("Schnorr benchmark loi sign: {}", err);
                return;
            }
        };
        let ok = schnorr::schnorr_verify(
            &curve,
            keypair.public_key,
            schnorr_message.as_bytes(),
            &sig,
        );
        if !ok {
            println!("Schnorr benchmark loi: verify false");
            return;
        }
    }
    let schnorr_total = schnorr_start.elapsed();

    println!("\nKet qua hieu nang:");
    print_perf_row("AES encrypt+decrypt", aes_total, aes_runs);
    print_perf_row("SHA-256 hash", sha_total, sha_runs);
    print_perf_row("ECC key generation", ecc_total, ecc_runs);
    print_perf_row("Schnorr sign+verify", schnorr_total, schnorr_runs);

    println!("\nDigest mau (SHA-256 tren payload benchmark): {}", last_digest);
    println!("\n================ KET THUC DEMO VA DANH GIA ================");
}