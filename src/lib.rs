use std::iter;

use aes::{
    cipher::{consts::U16, generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

mod ascii {
    const ASCII: &str = "abcdefghijklmnopqrstuvwxyz ";

    pub fn ix(c: char) -> usize {
        assert!(ASCII.contains(c.to_ascii_lowercase()));
        ASCII.find(c.to_ascii_lowercase()).unwrap()
    }
}

pub mod b64 {
    const B64DIC: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Encode a slice of bytes in base 64.
    pub fn encode(bytes: &[u8]) -> String {
        let mut b64s = String::new();

        for chunk in bytes.chunks(3) {
            let bytes: Vec<u8> = chunk.iter().chain([0, 0].iter()).cloned().take(3).collect();

            let part = sextets(&bytes);
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
                _ => unreachable!(),
            }
        }

        b64s
    }

    /// Decode a base64 string into a vector of bytes.
    pub fn decode(s: impl AsRef<str>) -> Result<Vec<u8>, String> {
        let b64txt = s.as_ref();
        let indices = b64txt
            .trim_end_matches('=')
            .chars()
            .map(|c| {
                let index = B64DIC
                    .find(c)
                    .ok_or_else(|| "invalid base64 string".to_string())?;
                Ok(index as u8)
            })
            .collect::<Result<Vec<u8>, String>>()?;
        let bytes = indices
            .chunks(4)
            .flat_map(|x| match x.len() {
                4 => {
                    let b0 = (x[0] << 2) | ((x[1] & 0b110000) >> 4);
                    let b1 = ((x[1] & 0b001111) << 4) | ((x[2] & 0b111100) >> 2);
                    let b2 = ((x[2] & 0b000011) << 6) | x[3];
                    vec![b0, b1, b2]
                }
                3 => {
                    let b0 = (x[0] << 2) | ((x[1] & 0b110000) >> 4);
                    let b1 = ((x[1] & 0b001111) << 4) | ((x[2] & 0b111100) >> 2);
                    vec![b0, b1]
                }
                2 => {
                    let b0 = (x[0] << 2) | ((x[1] & 0b110000) >> 4);
                    vec![b0]
                }
                _ => unreachable!(),
            })
            .collect();
        Ok(bytes)
    }

    fn sextets(triplet: &[u8]) -> (char, char, char, char) {
        (
            encode_single((triplet[0] & 0xfc) >> 2),
            encode_single(((triplet[0] & 0x3) << 4) | ((triplet[1] & 0xf0) >> 4)),
            encode_single(((triplet[1] & 0xf) << 2) | ((triplet[2] & 0xc0) >> 6)),
            encode_single(triplet[2] & 0x3f),
        )
    }

    fn encode_single(sextet: u8) -> char {
        assert!((sextet as usize) < B64DIC.len());
        B64DIC.chars().nth(sextet as usize).unwrap()
    }
}

/// Count the number of 1-valued bits in a byte slice.
fn bit_count(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .map(|&x| (0..=7).map(|i| (x as u32 & 2_u32.pow(i)) >> i).sum::<u32>())
        .sum()
}

/// Xor two equally long byte slices.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len()); // TODO: ???
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub mod hex {
    /// Parse a hexadecimal string into a vector of a bytes.
    pub fn parse(s: impl AsRef<str>) -> Result<Vec<u8>, String> {
        let hexstr = s.as_ref();
        if hexstr.len() % 2 != 0 {
            return Err("invalid hex string".to_string());
        }

        let bytes = hexstr
            .chars()
            .collect::<Vec<char>>()
            .chunks(2)
            .map(|pair| {
                let p0 = decode_single(pair[0])?;
                let p1 = decode_single(pair[1])?;
                Ok(p0 << 4 | p1)
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(bytes)
    }

    /// Get the hexadecimal representation of some bytes.
    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .flat_map(|&byte| {
                let b0 = encode_single((byte & 0xf0) >> 4).unwrap();
                let b1 = encode_single(byte & 0xf).unwrap();
                vec![b0, b1]
            })
            .collect()
    }

    /// Get the hexadecimal digit representation of a four-bit number.
    fn encode_single(value: u8) -> Result<char, String> {
        match value {
            0 => Ok('0'),
            1 => Ok('1'),
            2 => Ok('2'),
            3 => Ok('3'),
            4 => Ok('4'),
            5 => Ok('5'),
            6 => Ok('6'),
            7 => Ok('7'),
            8 => Ok('8'),
            9 => Ok('9'),
            10 => Ok('a'),
            11 => Ok('b'),
            12 => Ok('c'),
            13 => Ok('d'),
            14 => Ok('e'),
            15 => Ok('f'),
            _ => Err("invalid u8".to_string()),
        }
    }

    /// Get the decimal value of a single hexadecimal digit.
    fn decode_single(digit: char) -> Result<u8, String> {
        match digit {
            '0' => Ok(0),
            '1' => Ok(1),
            '2' => Ok(2),
            '3' => Ok(3),
            '4' => Ok(4),
            '5' => Ok(5),
            '6' => Ok(6),
            '7' => Ok(7),
            '8' => Ok(8),
            '9' => Ok(9),
            'a' => Ok(10),
            'b' => Ok(11),
            'c' => Ok(12),
            'd' => Ok(13),
            'e' => Ok(14),
            'f' => Ok(15),
            _ => Err("invalid hex string".to_string()),
        }
    }
}

pub fn english_score(text: &str) -> f32 {
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

// (score, key, text)
pub fn break_single_byte_xor(bytes: &[u8]) -> Result<(f32, u8, String), String> {
    let mut scores = vec![];

    for k in 0..=255u8 {
        let key: Vec<u8> = iter::repeat(k).take(bytes.len()).collect();
        match String::from_utf8(xor_bytes(bytes, &key)) {
            Ok(text) => scores.push((english_score(&text), k, text)),
            _ => continue,
        }
    }

    scores.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    if !scores.is_empty() {
        Ok(scores[0].clone())
    } else {
        Err("no valid utf8 strings found".to_string())
    }
}

pub fn build_repeated_key(b: &[u8], len: usize) -> Vec<u8> {
    iter::repeat(b).flatten().cloned().take(len).collect()
}

pub fn hamming(b0: &[u8], b1: &[u8]) -> u32 {
    bit_count(&xor_bytes(b0, b1))
}

// pad to multiple of size
pub fn pad_block(bytes: &[u8], mut size: usize) -> Vec<u8> {
    let len = bytes.len();
    while size < len {
        size *= 2;
    }
    let mut bytes = bytes.to_vec();
    let diff = size % len;
    if diff > 0 {
        bytes.resize(len + diff, diff as u8);
    }
    bytes
}

pub fn aes_decrypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let key: &GenericArray<_, U16> = GenericArray::from_slice(key);
    let cipher = Aes128::new(&key);
    let mut blocks = bytes
        .chunks(key.len())
        .map(|b| GenericArray::from_slice(b).to_owned())
        .collect::<Vec<_>>();
    cipher.decrypt_blocks(blocks.as_mut_slice());
    blocks.iter().cloned().flatten().collect()
}

#[cfg(test)]
mod tests {
    use crate::b64;
    use crate::pad_block;

    #[test]
    fn test_pad_block() {
        assert_eq!(
            &pad_block(b"YELLOW SUBMARINE", 20),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
        assert_eq!(
            &pad_block(b"YELLOW SUBMARINE", 12),
            b"YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08"
        );
        assert_eq!(&pad_block(b"YELLOW SUBMARINE", 16), b"YELLOW SUBMARINE");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(b64::encode("".as_bytes()), "");
        assert_eq!(b64::encode("f".as_bytes()), "Zg==");
        assert_eq!(b64::encode("fo".as_bytes()), "Zm8=");
        assert_eq!(b64::encode("foo".as_bytes()), "Zm9v");
        assert_eq!(b64::encode("foob".as_bytes()), "Zm9vYg==");
        assert_eq!(b64::encode("fooba".as_bytes()), "Zm9vYmE=");
        assert_eq!(b64::encode("foobar".as_bytes()), "Zm9vYmFy");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(
            String::from_utf8(b64::decode("Zm9vYmFy").unwrap()).unwrap(),
            "foobar"
        );
        assert_eq!(
            String::from_utf8(b64::decode("Zm9vYmE=").unwrap()).unwrap(),
            "fooba"
        );
        assert_eq!(
            String::from_utf8(b64::decode("Zm9vYg==").unwrap()).unwrap(),
            "foob"
        );
        assert_eq!(
            String::from_utf8(b64::decode("Zm9v").unwrap()).unwrap(),
            "foo"
        );
        assert_eq!(
            String::from_utf8(b64::decode("Zm8=").unwrap()).unwrap(),
            "fo"
        );
        assert_eq!(
            String::from_utf8(b64::decode("Zg==").unwrap()).unwrap(),
            "f"
        );
        assert_eq!(String::from_utf8(b64::decode("").unwrap()).unwrap(), "");
    }
}
