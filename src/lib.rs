use std::iter;

pub mod aes;
pub mod b64;
pub mod hex;
pub mod pad;
pub mod rand;
pub mod xor;

mod ascii {
    const ASCII: &str = "abcdefghijklmnopqrstuvwxyz ";

    pub fn ix(c: char) -> usize {
        assert!(ASCII.contains(c.to_ascii_lowercase()));
        ASCII.find(c.to_ascii_lowercase()).unwrap()
    }
}

/// Count the number of 1-valued bits in a byte slice.
fn bit_count(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .map(|&x| (0..=7).map(|i| (x as u32 & 2_u32.pow(i)) >> i).sum::<u32>())
        .sum()
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
        match String::from_utf8(xor::xor_bytes(bytes, &key)) {
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
    bit_count(&xor::xor_bytes(b0, b1))
}

#[cfg(test)]
mod tests {}
