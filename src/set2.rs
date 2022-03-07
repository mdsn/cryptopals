/// The Cryptopals challenges, set 2.

use cryptopals::{pad_block};

fn challenge9() {
    let b = b"YELLOW SUBMARINE";
    let padded = pad_block(b, 20);
    assert_eq!(&padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}

fn main() {
    challenge9();
}