/// Repeated-key xor
extern crate cryptopals;

use std::env;
use std::io::{self, Read};

use cryptopals::{build_repeated_key, hex, xor_bytes};

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("wrong args");
        return;
    }
    let key = &args[1];
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer).unwrap();
    let bytes = buffer.as_bytes();
    let repkey = build_repeated_key(key, bytes.len());
    let hexstr = hex::encode(&xor_bytes(bytes, repkey.as_bytes()));
    println!("{}", hexstr);
}
