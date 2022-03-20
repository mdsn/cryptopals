#[macro_use]
extern crate log;

use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use cryptopals::aes;
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

// Encrypt bytes under a random key
fn encryption_oracle(bytes: &[u8]) -> (aes::CipherMode, Vec<u8>) {
    let mut prng = rand::make_prng();
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
        (aes::CipherMode::CBC, aes::encrypt_cbc(&bytes, &key, &iv))
    } else {
        (aes::CipherMode::ECB, aes::encrypt_ecb(&bytes, &key))
    }
}

fn detection_oracle(bytes: &[u8]) -> aes::CipherMode {
    match aes::detect_ecb(bytes) {
        true => aes::CipherMode::ECB,
        false => aes::CipherMode::CBC,
    }
}

fn challenge11() {
    let plaintext = rand::bytes(16 * 64);

    let mut matches: u32 = 0;
    let mut ecb_failed: u32 = 0; // failed to detect ecb
    let mut cbc_failed: u32 = 0; // failed to detect cbc
    let mut total_cbc: u32 = 0;

    const RUNS: u32 = 100;

    for _ in 0..RUNS {
        let (mode, bytes) = encryption_oracle(&plaintext);
        if mode == aes::CipherMode::CBC {
            total_cbc += 1;
        }

        if detection_oracle(&bytes) == mode {
            matches += 1;
        } else if mode == aes::CipherMode::CBC {
            cbc_failed += 1;
        } else {
            ecb_failed += 1;
        }
    }

    info!(
        "challenge11: {} matches out of {} ({}%) / failed to detect cbc:ebc {}:{} / cbc:ecb {}:{}",
        matches,
        RUNS,
        matches as f32 / 10.0,
        cbc_failed,
        ecb_failed,
        total_cbc,
        RUNS - total_cbc
    );
}

fn main() {
    env_logger::init();

    challenge9();
    challenge10();
    challenge11();
}
