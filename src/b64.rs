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

/// Encode 3 bytes as 4 base64 characters
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

#[cfg(test)]
mod tests {
    use super::{encode, decode};

    #[test]
    fn test_base64_encode() {
        assert_eq!(encode("".as_bytes()), "");
        assert_eq!(encode("f".as_bytes()), "Zg==");
        assert_eq!(encode("fo".as_bytes()), "Zm8=");
        assert_eq!(encode("foo".as_bytes()), "Zm9v");
        assert_eq!(encode("foob".as_bytes()), "Zm9vYg==");
        assert_eq!(encode("fooba".as_bytes()), "Zm9vYmE=");
        assert_eq!(encode("foobar".as_bytes()), "Zm9vYmFy");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(
            String::from_utf8(decode("Zm9vYmFy").unwrap()).unwrap(),
            "foobar"
        );
        assert_eq!(
            String::from_utf8(decode("Zm9vYmE=").unwrap()).unwrap(),
            "fooba"
        );
        assert_eq!(
            String::from_utf8(decode("Zm9vYg==").unwrap()).unwrap(),
            "foob"
        );
        assert_eq!(
            String::from_utf8(decode("Zm9v").unwrap()).unwrap(),
            "foo"
        );
        assert_eq!(
            String::from_utf8(decode("Zm8=").unwrap()).unwrap(),
            "fo"
        );
        assert_eq!(
            String::from_utf8(decode("Zg==").unwrap()).unwrap(),
            "f"
        );
        assert_eq!(String::from_utf8(decode("").unwrap()).unwrap(), "");
    }
}