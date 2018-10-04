/// The Cryptopals challenges, set 1, challenges 1 through 5.
extern crate cryptopals;

use std::fs::File;
use std::io::{BufRead, BufReader};

use cryptopals::{break_single_byte_xor, build_repeated_key, Bytes};

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
