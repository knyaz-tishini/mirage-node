/// Generate an X25519 keypair or derive public key from private key.
///
/// Usage:
///   keygen                       — generate new keypair (plain text)
///   keygen --json                — generate new keypair (JSON)
///   keygen pubkey <hex_privkey>  — derive public key from private key
use mirage_core::crypto::KeyPair;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 3 && args[1] == "pubkey" {
        let bytes = hex_decode(&args[2]);
        let kp = KeyPair::from_secret(bytes);
        println!("{}", hex_encode(kp.public.to_bytes()));
        return;
    }

    let json = args.iter().any(|a| a == "--json");
    let kp = KeyPair::generate();
    let private_hex = hex_encode(kp.secret.to_bytes());
    let public_hex = hex_encode(kp.public.to_bytes());

    if json {
        println!(
            r#"{{"private_key": "{}", "public_key": "{}"}}"#,
            private_hex, public_hex
        );
    } else {
        println!("Private key: {}", private_hex);
        println!("Public key:  {}", public_hex);
    }
}

fn hex_encode(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> [u8; 32] {
    assert!(s.len() == 64, "expected 64-char hex string, got {}", s.len());
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("invalid hex at pos {}", i * 2));
    }
    out
}
