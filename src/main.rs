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
    let _mssv = "067206006852";
    let _full_name = "Nhu Pham Quang Manh";
    let _schnorr_message = "Schnorr demo message";

    println!("\n[1] DEMO HE THONG");

    println!("\n--- AES-128 Demo ---");
    let initial_counter = [0u8; 16];
    let cipher_bytes = aes::aes_128_ctr_encrypt(plaintext.as_bytes(), aes_key, initial_counter);
    println!("Key: {}", aes_key);
    println!("Plaintext: {}", plaintext);
    println!("Mode: CTR");
    println!("Initial counter: {:02X?}", initial_counter);
    print!("Ciphertext (hex): ");
    for byte in &cipher_bytes {
        print!("{:02x}", byte);
    }
    println!();

    let decrypted_bytes = aes::aes_128_ctr_decrypt(&cipher_bytes, aes_key, initial_counter);
    let decrypted = String::from_utf8_lossy(&decrypted_bytes).into_owned();
    println!("Decrypted: {}", decrypted);

    let message = plaintext;
    let digest = sha256::sha256(message.as_bytes());

    println!("\n--- SHA-256 Demo ---");
    println!("Input: {}", message);
    println!("SHA-256: {}", digest);

    println!("\n--- ECC Personal Curve Demo ---");

    println!("\n--- Schnorr Signature Demo ---");

    println!("\n[2] DANH GIA HIEU NANG");
    println!("Thong so: key='{}', plaintext='{}'", aes_key, plaintext);

    let perf_plaintext = plaintext.repeat(8);

    let aes_runs = 500u32;
    let aes_start = Instant::now();
    for _ in 0..aes_runs {
        let c = aes::aes_128_ctr_encrypt(perf_plaintext.as_bytes(), aes_key, initial_counter);
        let p = aes::aes_128_ctr_decrypt(&c, aes_key, initial_counter);
        if p != perf_plaintext.as_bytes() {
            println!("AES benchmark loi: decrypt khong khop plaintext");
            return;
        }
    }
    let aes_total = aes_start.elapsed();

    let sha_runs = 20_000u32;
    let sha_start = Instant::now();
    for _ in 0..sha_runs {
        sha256::sha256(perf_plaintext.as_bytes());
    }
    let sha_total = sha_start.elapsed();

    print_perf_row("SHA-256", sha_total, sha_runs);
    print_perf_row("AES-128 (CTR mode)", aes_total, aes_runs);

    println!("Schnorr va ECC benchmarks se duoc cap nhat");

    println!("\n================ KET THUC DEMO VA DANH GIA ================");
}