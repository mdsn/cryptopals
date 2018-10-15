use std::iter;
use std::string::FromUtf8Error;

mod ascii {
    const ASCII: &str = "abcdefghijklmnopqrstuvwxyz ";

    pub fn ix(c: char) -> usize {
        assert!(ASCII.contains(c.to_ascii_lowercase()));
        ASCII.find(c.to_ascii_lowercase()).unwrap()
    }
}

mod b64 {
    const B64DIC: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn sextets(triplet: &[u8]) -> (char, char, char, char) {
        (
            val((triplet[0] & 0xfc) >> 2),
            val(((triplet[0] & 0x3) << 4) | ((triplet[1] & 0xf0) >> 4)),
            val(((triplet[1] & 0xf) << 2) | ((triplet[2] & 0xc0) >> 6)),
            val(triplet[2] & 0x3f),
        )
    }

    fn val(sextet: u8) -> char {
        assert!((sextet as usize) < B64DIC.len());
        B64DIC.chars().nth(sextet as usize).unwrap()
    }
}

mod hex {
    const HEXDIC: &str = "0123456789abcdef";

    pub fn encode_single(val: u8) -> char {
        assert!(val < 16);
        HEXDIC.chars().nth(val as usize).unwrap()
    }

    pub fn val(h: char) -> u8 {
        assert!(HEXDIC.contains(h));
        HEXDIC.find(h).unwrap() as u8
    }
}

#[derive(Clone)]
pub struct Bytes {
    m: Vec<u8>,
}

#[allow(dead_code)]
impl Bytes {
    pub fn len(&self) -> usize {
        self.m.len()
    }

    pub fn from_hex(hex: &str) -> Bytes {
        assert!(hex.len() % 2 == 0, "odd number of digits in hex string");
        Bytes {
            m: hex
                .chars()
                .collect::<Vec<char>>()
                .chunks(2)
                .map(|pair| hex::val(pair[0]) << 4 | hex::val(pair[1]))
                .collect(),
        }
    }

    pub fn from_str(s: &str) -> Bytes {
        Bytes {
            m: Vec::from(s.as_bytes()),
        }
    }

    pub fn from_slice(s: &[u8]) -> Bytes {
        Bytes { m: Vec::from(s) }
    }

    pub fn b64_encode(&self) -> String {
        let mut b64s = String::new();

        for chunk in self.m.chunks(3) {
            let bytes: Vec<u8> = chunk.iter().chain([0, 0].iter()).cloned().take(3).collect();

            let part = b64::sextets(&bytes);
            b64s.push(part.0);
            b64s.push(part.1);

            match chunk.len() {
                1 => b64s.push_str("=="),
                2 => {
                    b64s.push(part.2);
                    b64s.push('=');
                }
                3 => {
                    b64s.push(part.2);
                    b64s.push(part.3);
                }
                _ => {}
            }
        }

        b64s
    }

    pub fn hex_encode(&self) -> String {
        self.m
            .iter()
            .flat_map(|&byte| {
                vec![
                    hex::encode_single((byte & 0xf0) >> 4),
                    hex::encode_single(byte & 0xf),
                ]
            })
            .collect()
    }

    pub fn to_string(&self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.m.clone())
    }

    pub fn xor(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        let bytes: Vec<u8> = self
            .m
            .iter()
            .zip(other.m.iter())
            .map(|(x, y)| x ^ y)
            .collect();
        Bytes::from_slice(&bytes)
    }

    pub fn bit_count(&self) -> u32 {
        self.m
            .iter()
            .map(|&x| (0..=7).map(|i| (x as u32 & 2_u32.pow(i)) >> i).sum::<u32>())
            .sum()
    }
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
        .map(|c| english_freq[ascii::ix(c)])
        .sum()
}

pub fn break_single_byte_xor(payload: &Bytes) -> Option<(f32, String)> {
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

pub fn build_repeated_key(s: &str, len: usize) -> String {
    iter::repeat(s)
        .map(|k| k.chars())
        .flatten()
        .take(len)
        .collect()
}

pub fn hamming(b0: &Bytes, b1: &Bytes) -> u32 {
    b0.xor(b1).bit_count()
}
