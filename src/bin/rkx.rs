/// Repeated-key xor
extern crate cryptopals;

use std::env;
use std::io::{self, Read};

use cryptopals::{build_repeated_key, Bytes};

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("wrong args");
        return;
    }
    let key = &args[1];
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer).unwrap();
    let bytes = Bytes::from_str(&buffer);
    let repkey = Bytes::from_str(&build_repeated_key(key, bytes.len()));
    println!("{}", bytes.xor(&repkey).hex_encode());
}
