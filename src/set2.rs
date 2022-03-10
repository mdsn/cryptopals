use std::{
    fs::File,
    io::{BufRead, BufReader},
};

/// The Cryptopals challenges, set 2.
use cryptopals::{aes_decrypt_cbc, b64, pad_block};

fn challenge9() {
    let b = b"YELLOW SUBMARINE";
    let padded = pad_block(b, 20);
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
    let dec = aes_decrypt_cbc(&ct, b"YELLOW SUBMARINE", &[0u8; 16]);
    let s = String::from_utf8(dec).unwrap();
    assert!(s.starts_with("I'm back and I'm ringin' the bell"));
}

fn main() {
    challenge9();
    challenge10();
}
