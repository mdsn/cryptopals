use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
};

use cryptopals::aes;
/// The Cryptopals challenges, set 2.
use cryptopals::b64;
use cryptopals::pad;
use cryptopals::rand;

fn challenge9() {
    let b = b"YELLOW SUBMARINE";
    let padded = pad::pad_block(b, 20);
    assert_eq!(&padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}

fn read_concat_lines(filename: &str) -> String {
    BufReader::new(File::open(filename).unwrap())
        .lines()
        .map(|l| l.unwrap())
        .reduce(|mut a, b| {
            a.push_str(&b);
            a
        })
        .unwrap()
}

fn challenge10() {
    let ct = b64::decode(&read_concat_lines("10.txt")).unwrap();
    let dec = aes::decrypt_cbc(&ct, b"YELLOW SUBMARINE", &[0u8; 16]);
    let s = String::from_utf8(dec).unwrap();
    assert!(s.starts_with("I'm back and I'm ringin' the bell"));
}

fn make_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

// Encrypt bytes under a random key
fn encryption_oracle(bytes: &[u8]) -> Vec<u8> {
    let mut prng = rand::Xoshiro256::new(make_seed());
    // prepend and append 5 to 10 random bytes
    let (lo, hi) = (prng.range(5) + 5, prng.range(5) + 5);
    let bytes: Vec<u8> = prng
        .get_bytes(lo)
        .iter()
        .chain(bytes.iter())
        .chain(prng.get_bytes(hi).iter())
        .cloned()
        .collect();

    let key = prng.get_bytes(16);
    if prng.bool() {
        let iv = prng.get_bytes(16);
        aes::encrypt_cbc(&bytes, &key, &iv)
    } else {
        aes::encrypt_ecb(&bytes, &key)
    }
}

fn challenge11() {
    let pt = b"Honestly, we hacked most of it together with Perl.";
    let bytes = encryption_oracle(pt);
    let encoded = b64::encode(&bytes);
    println!("{}", encoded);
}

fn main() {
    // challenge9();
    // challenge10();
    challenge11();
}
