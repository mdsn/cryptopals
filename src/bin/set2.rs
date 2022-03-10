use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use cryptopals::pad;
/// The Cryptopals challenges, set 2.
use cryptopals::b64;
use cryptopals::aes;

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

fn main() {
    challenge9();
    challenge10();
}
