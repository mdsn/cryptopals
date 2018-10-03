const B64DIC: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HEXDIC: &str = "0123456789abcdef";

fn hex_val(h: char) -> u8 {
    assert!(HEXDIC.contains(h));
    HEXDIC.find(h).unwrap() as u8
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

struct Bytes { m: Vec<u8> }

impl Bytes {
    fn from_hex(hex: &str) -> Bytes {
        assert!(hex.len() % 2 == 0, "odd number of digits in hex string");
        let mut buf = Vec::new();
        let mut iter = hex.chars();
        while let Some(h1) = iter.next() {
            let h0 = iter.next().unwrap();
            let byte: u8 = hex_val(h1) << 4 | hex_val(h0);
            buf.push(byte); 
        }
        Bytes { m: buf }
    }

    fn from_str(s: &str) -> Bytes {
        Bytes { m: Vec::from(s.as_bytes()) }
    }

    fn b64encode(&self) -> String {
        let mut i: usize = 0;
        let mut b64 = String::new();

        while i < self.m.len() {
            let last_chunk = i + 3 > self.m.len();
            let slice = if last_chunk {
                &self.m[i..]
            } else {
                &self.m[i..i+3]
            };

            let mut bytes = [0u8; 3];
            for (i, &byte) in slice.iter().enumerate() {
                bytes[i] = byte;
            }

            b64.push(b64_val(b64_1st_sextet(&bytes)));
            b64.push(b64_val(b64_2nd_sextet(&bytes)));

            if !last_chunk {
                b64.push(b64_val(b64_3rd_sextet(&bytes)));
                b64.push(b64_val(b64_4th_sextet(&bytes)));
            } else {
                let missing = 3 - slice.len();

                if missing == 1 {
                    b64.push(b64_val(b64_3rd_sextet(&bytes)));
                    b64.push('=');
                } else {
                    b64.push_str("==");
                }
            }

            i += 3;
        }

        b64
    }
}

fn main() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c\
                 696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let inputs = ["", "f", "fo", "foo", "foob", "fooba", "foobar"];
    for &input in inputs.iter() {
        println!("{}", Bytes::from_str(input).b64encode());
    }
}
