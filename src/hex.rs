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
