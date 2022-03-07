/// The Cryptopals challenges, set 1.
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};

use cryptopals::{b64, break_single_byte_xor, build_repeated_key, hamming, hex, xor_bytes, aes_decrypt};

fn challenge1() {
    let bytes = hex::parse(
        "49276d206b696c6c696e6720796f757220627261696e206c\
         696b65206120706f69736f6e6f7573206d757368726f6f6d",
    )
    .unwrap();
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        b64::encode(&bytes)
    );
}

fn challenge2() {
    let b1 = hex::parse("1c0111001f010100061a024b53535009181c").unwrap();
    let b2 = hex::parse("686974207468652062756c6c277320657965").unwrap();
    let b3 = xor_bytes(&b1, &b2);
    assert_eq!("746865206b696420646f6e277420706c6179", hex::encode(&b3));
}

fn challenge3() {
    let bytes =
        hex::parse("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
    if let Ok((_, _, broken)) = break_single_byte_xor(&bytes) {
        assert_eq!("Cooking MC's like a pound of bacon", broken);
    }
}

fn challenge4() {
    let txt = File::open("4.txt").unwrap();
    let mut scores: Vec<_> = BufReader::new(txt)
        .lines()
        .flatten()
        .map(|line| {
            let bytes = hex::parse(line).unwrap();
            break_single_byte_xor(&bytes)
        })
        .flatten()
        .collect();
    scores.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    assert_eq!("Now that the party is jumping\n", scores[0].2)
}

fn challenge5() {
    let bytes =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();
    let key = build_repeated_key(b"ICE", bytes.len());
    let encrypted = xor_bytes(bytes, &key);
    assert_eq!(
        hex::encode(&encrypted),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
         a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );
}

fn find_xor_key_size(bytes: &[u8]) -> usize {
    let mut mindist = f32::MAX;
    let mut keysize: usize = 0;
    for candidate in 2..=40 {
        let chunks: Vec<_> = bytes.chunks(candidate).take(4).collect();
        let mut dist = 0f32;
        for i in 0..4 {
            for j in 0..4 {
                dist += hamming(chunks[i], chunks[j]) as f32;
            }
        }
        dist = dist / candidate as f32;
        if dist < mindist {
            keysize = candidate;
            mindist = dist;
        }
    }
    keysize
}

fn find_repxor_key(bytes: &[u8], keysize: usize) -> Result<Vec<u8>, String> {
    let blocks = bytes.chunks(keysize).collect::<Vec<_>>();
    let mut keybytes = vec![];
    for i in 0..keysize {
        let mut transposed = vec![];
        for b in &blocks {
            if b.len() <= i {
                break;
            }
            transposed.push(b[i]);
        }
        let (_, key, _) = break_single_byte_xor(&transposed)?;
        keybytes.push(key);
    }

    Ok(keybytes)
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

fn challenge6() {
    let b0 = "this is a test".as_bytes();
    let b1 = "wokka wokka!!!".as_bytes();
    assert_eq!(37, hamming(b0, b1));

    let b64txt = read_concat_lines("6.txt");
    let bytes = b64::decode(&b64txt).unwrap();
    let keysize = find_xor_key_size(&bytes);

    let key = build_repeated_key(&find_repxor_key(&bytes, keysize).unwrap(), bytes.len());
    let pt = String::from_utf8(xor_bytes(&bytes, &key)).unwrap();
    assert!(pt.starts_with("I'm back and I'm ringin' the bell"));
}

fn challenge7() {
    let key = b"YELLOW SUBMARINE";
    let bytes = b64::decode(&read_concat_lines("7.txt")).unwrap();
    let bytes = aes_decrypt(&bytes, key);
    let pt = String::from_utf8(bytes).unwrap();
    assert!(pt.starts_with("I'm back and I'm ringin' the bell"));
}

fn detect_ecb(bytes: &[u8], block_size: usize) -> bool {
    if bytes.len() % block_size != 0 {
        panic!("detect_ecb: bytes len not multiple of block_size");
    }
    let mut seen = HashSet::new();
    for block in bytes.chunks(block_size) {
        let bs = block.to_vec();
        if seen.contains(&bs) {
            return true;
        }
        seen.insert(bs);
    }
    false
}

fn challenge8() {
    let lines = BufReader::new(File::open("8.txt").unwrap())
        .lines()
        .flatten()
        .flat_map(|s| hex::parse(s));
    for (i, bytes) in lines.enumerate() {
        if detect_ecb(&bytes, 16) {
            assert_eq!(i, 132);
        }
    }
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
    challenge4();
    challenge5();
    challenge6();
    challenge7();
    challenge8();
}
