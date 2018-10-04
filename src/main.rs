use std::f32;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter;
use std::ops::BitXor;

const B64DIC: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HEXDIC: &str = "0123456789abcdef";
const ASCII: &str = "abcdefghijklmnopqrstuvwxyz ";

fn ascii_ix(c: char) -> usize {
    assert!(ASCII.contains(c));
    ASCII.find(c.to_ascii_lowercase()).unwrap()
}

fn hex_val(h: char) -> u8 {
    assert!(HEXDIC.contains(h));
    HEXDIC.find(h).unwrap() as u8
}

fn hex_char(val: u8) -> char {
    assert!(val < 16);
    HEXDIC.chars().nth(val as usize).unwrap()
}

fn b64_val(sextet: u8) -> char {
    assert!((sextet as usize) < B64DIC.len());
    B64DIC.chars().nth(sextet as usize).unwrap()
}

fn b64_1st_sextet(bytes: &[u8]) -> u8 {
    (bytes[0] & 0xfc) >> 2
}
fn b64_2nd_sextet(bytes: &[u8]) -> u8 {
    ((bytes[0] & 0x3) << 4) | ((bytes[1] & 0xf0) >> 4)
}
fn b64_3rd_sextet(bytes: &[u8]) -> u8 {
    ((bytes[1] & 0xf) << 2) | ((bytes[2] & 0xc0) >> 6)
}
fn b64_4th_sextet(bytes: &[u8]) -> u8 {
    bytes[2] & 0x3f
}

#[derive(Clone)]
struct Bytes { m: Vec<u8> }

#[allow(dead_code)]
impl Bytes {
    fn len(&self) -> usize {
        self.m.len()
    }

    fn from_hex(hex: &str) -> Bytes {
        assert!(hex.len() % 2 == 0, "odd number of digits in hex string");
        let mut buf = Vec::new();
        let mut iter = hex.chars();
        while let Some(h1) = iter.next() {
            let h0 = iter.next().unwrap();
            let byte: u8 = hex_val(h1) << 4 | hex_val(h0);
            buf.push(byte); 
        }
        Bytes { m: buf }
    }

    fn from_str(s: &str) -> Bytes {
        Bytes { m: Vec::from(s.as_bytes()) }
    }

    fn from_slice(s: &[u8]) -> Bytes {
        Bytes { m: Vec::from(s) }
    }

    fn b64_encode(&self) -> String {
        let mut i: usize = 0;
        let mut b64 = String::new();

        while i < self.len() {
            let last_chunk = i + 3 > self.len();
            let slice = if last_chunk {
                &self.m[i..]
            } else {
                &self.m[i..i+3]
            };

            let mut bytes = [0u8; 3];
            for (i, &byte) in slice.iter().enumerate() {
                bytes[i] = byte;
            }

            b64.push(b64_val(b64_1st_sextet(&bytes)));
            b64.push(b64_val(b64_2nd_sextet(&bytes)));

            if !last_chunk {
                b64.push(b64_val(b64_3rd_sextet(&bytes)));
                b64.push(b64_val(b64_4th_sextet(&bytes)));
            } else {
                let missing = 3 - slice.len();

                if missing == 1 {
                    b64.push(b64_val(b64_3rd_sextet(&bytes)));
                    b64.push('=');
                } else {
                    b64.push_str("==");
                }
            }

            i += 3;
        }

        b64
    }

    fn hex_encode(&self) -> String {
        let mut s = String::new();
        for &byte in self.m.iter() {
            let ls = byte & 0xf;
            let ms = (byte & 0xf0) >> 4;
            s.push(hex_char(ms));
            s.push(hex_char(ls));
        }
        s
    }

    fn to_string(&self) -> String {
        String::from_utf8(self.m.iter().cloned().collect()).unwrap_or("".to_string())
    }
}

impl BitXor for Bytes {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        assert_eq!(self.len(), rhs.len());
        let bytes: Vec<u8> = self.m.iter()
            .zip(rhs.m.iter())
            .map(|(x, y)| x ^ y)
            .collect();
        Bytes::from_slice(&bytes)
    }
}

fn challenge1() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c\
                 696b65206120706f69736f6e6f7573206d757368726f6f6d";
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        Bytes::from_hex(hex).b64_encode()
    );
}

fn challenge2() {
    let h1 = "1c0111001f010100061a024b53535009181c";
    let h2 = "686974207468652062756c6c277320657965";

    let b1 = Bytes::from_hex(h1);
    let b2 = Bytes::from_hex(h2);
    let b3 = b1 ^ b2;
    assert_eq!("746865206b696420646f6e277420706c6179", b3.hex_encode());
}

fn break_single_byte_xor(payload: &Bytes) -> (f32, String) {
    let english_freq = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  // A-G
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  // H-N
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  // O-U
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.13000       // V-Z, ' '
    ];
    let mut scores: Vec<(f32, String)> = Vec::new();

    for k in 0..=255u8 {
        let key: Vec<u8> = iter::repeat(k).take(payload.len()).collect();
        let bytes = Bytes::from_slice(&key);
        let result_str = (payload.clone() ^ bytes).to_string();
        if result_str.len() == 0 {
            continue;
        }

        let score = result_str.chars()
            .filter(|&c| c.is_ascii_alphabetic() || c == ' ')
            .map(|c| english_freq[ascii_ix(c.to_ascii_lowercase())])
            .sum();
        scores.push((score, result_str));
    }

    scores.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    scores[0].clone()
}

fn challenge3() {
    let hex =
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let payload = Bytes::from_hex(hex);
    let (score, broken) = break_single_byte_xor(&payload);
    assert_eq!("Cooking MC's like a pound of bacon", broken);
}

fn challenge4() {
    // let txt = File::open("4.txt").unwrap();
    let hex = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f";
    let payload = Bytes::from_hex(hex);
    let (_, broken) = break_single_byte_xor(&payload);
    assert_eq!("Now that the party is jumping\n", broken)
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
    challenge4();
}
