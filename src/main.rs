mod sha256;
mod ecc;
mod exchange_key;
mod schnorr;

fn main() {
    let message = "abc";
    let digest = sha256::sha256(message.as_bytes());

    println!("Input: {}", message);
    println!("SHA-256: {}", digest);

    println!("\n--- ECC Personal Curve Demo ---");
    let mssv = "067206006852";
    let full_name = "Nhu Pham Quang Manh";

    match ecc::demo_personal_curve(mssv, full_name) {
        Ok(report) => println!("{}", report),
        Err(err) => println!("Loi tao curve: {}", err),
    }

    println!("\n--- ECDH Exchange Demo ---");
    match exchange_key::demo_ecdh_exchange(mssv, full_name) {
        Ok(report) => println!("{}", report),
        Err(err) => println!("Loi trao doi khoa: {}", err),
    }

    println!("\n--- Schnorr Signature Demo ---");
    let schnorr_message = "Schnorr demo message";
    match schnorr::demo_schnorr(mssv, full_name, schnorr_message) {
        Ok(report) => println!("{}", report),
        Err(err) => println!("Loi Schnorr: {}", err),
    }
}