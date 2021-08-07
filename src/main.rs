/// The Cryptopals challenges, set 1, challenges 1 through 5.
extern crate cryptopals;

use std::fs::File;
use std::io::{BufRead, BufReader};

use cryptopals::{b64, break_single_byte_xor, build_repeated_key, hamming, hex, xor_bytes};

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
    if let Ok((_, broken)) = break_single_byte_xor(&bytes) {
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
    scores.sort_by(|(a, _), (b, _)| b.partial_cmp(&a).unwrap());
    assert_eq!("Now that the party is jumping\n", scores[0].1)
}

fn challenge5() {
    let bytes =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();
    let key = build_repeated_key("ICE", bytes.len());
    let encrypted = xor_bytes(bytes, key.as_bytes());
    assert_eq!(
        hex::encode(&encrypted),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
         a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );
}

fn challenge6() {
    let b0 = "this is a test".as_bytes();
    let b1 = "wokka wokka!!!".as_bytes();
    assert_eq!(37, hamming(b0, b1));
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
    challenge4();
    challenge5();
    challenge6();
}
