use std::f32;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter;
use std::string::FromUtf8Error;

const B64DIC: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
fn b64_sextets(triplet: &[u8]) -> (char, char, char, char) {
    (
        b64_val(b64_1st_sextet(triplet)),
        b64_val(b64_2nd_sextet(triplet)),
        b64_val(b64_3rd_sextet(triplet)),
        b64_val(b64_4th_sextet(triplet)),
    )
}

#[derive(Clone)]
struct Bytes {
    m: Vec<u8>,
}

#[allow(dead_code)]
impl Bytes {
    fn len(&self) -> usize {
        self.m.len()
    }

    fn from_hex(hex: &str) -> Bytes {
        assert!(hex.len() % 2 == 0, "odd number of digits in hex string");
        Bytes {
            m: hex
                .chars()
                .collect::<Vec<char>>()
                .chunks(2)
                .map(|pair| hex_val(pair[0]) << 4 | hex_val(pair[1]))
                .collect(),
        }
    }

    fn from_str(s: &str) -> Bytes {
        Bytes {
            m: Vec::from(s.as_bytes()),
        }
    }

    fn from_slice(s: &[u8]) -> Bytes {
        Bytes { m: Vec::from(s) }
    }

    fn b64_encode(&self) -> String {
        let mut b64 = String::new();

        for chunk in self.m.chunks(3) {
            let mut bytes = [0u8; 3];
            for (i, &byte) in chunk.iter().enumerate() {
                bytes[i] = byte;
            }

            let part = b64_sextets(&bytes);
            b64.push(part.0);
            b64.push(part.1);

            match chunk.len() {
                1 => b64.push_str("=="),
                2 => {
                    b64.push(part.2);
                    b64.push('=');
                }
                3 => {
                    b64.push(part.2);
                    b64.push(part.3);
                }
                _ => {}
            }
        }

        b64
    }

    fn hex_encode(&self) -> String {
        self.m
            .iter()
            .flat_map(|&byte| vec![hex_char((byte & 0xf0) >> 4), hex_char(byte & 0xf)])
            .collect()
    }

    fn to_string(&self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.m.clone())
    }

    fn xor(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        let bytes: Vec<u8> = self
            .m
            .iter()
            .zip(other.m.iter())
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
    let b3 = b1.xor(&b2);
    assert_eq!("746865206b696420646f6e277420706c6179", b3.hex_encode());
}

fn english_score(text: &str) -> f32 {
    let english_freq = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.13000, // V-Z, ' '
    ];
    text.chars()
        .filter(|&c| c.is_ascii_alphabetic() || c == ' ')
        .map(|c| english_freq[ascii_ix(c.to_ascii_lowercase())])
        .sum()
}

fn break_single_byte_xor(payload: &Bytes) -> Option<(f32, String)> {
    let mut scores: Vec<(f32, String)> = Vec::new();

    for k in 0..=255u8 {
        let key: Vec<u8> = iter::repeat(k).take(payload.len()).collect();
        let bytes = Bytes::from_slice(&key);
        match (payload.xor(&bytes)).to_string() {
            Ok(text) => scores.push((english_score(&text), text)),
            _ => continue,
        }
    }

    scores.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    if scores.len() > 0 {
        Some(scores[0].clone())
    } else {
        None
    }
}

fn challenge3() {
    let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let payload = Bytes::from_hex(hex);
    match break_single_byte_xor(&payload) {
        Some((_, broken)) => assert_eq!("Cooking MC's like a pound of bacon", broken),
        None => {}
    }
}

fn challenge4() {
    let txt = File::open("4.txt").unwrap();
    let mut scores: Vec<_> = BufReader::new(txt)
        .lines()
        .filter_map(|hex| {
            let payload = Bytes::from_hex(&hex.unwrap());
            break_single_byte_xor(&payload)
        })
        .collect();
    scores.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    assert_eq!("Now that the party is jumping\n", scores[0].1)
}

fn build_repeated_key(s: &str, len: usize) -> String {
    iter::repeat(s)
        .map(|k| k.chars())
        .flatten()
        .take(len)
        .collect()
}

fn challenge5() {
    let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let payload = Bytes::from_str(input);
    let key = Bytes::from_str(&build_repeated_key("ICE", payload.len()));
    let encrypted = payload.xor(&key);
    assert_eq!(
        encrypted.hex_encode(),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
         a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
    challenge4();
    challenge5();
}
