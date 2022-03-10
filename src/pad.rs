// pad to multiple of size
pub fn pad_block(bytes: &[u8], mut size: usize) -> Vec<u8> {
    let len = bytes.len();
    while size < len {
        size *= 2;
    }
    let mut bytes = bytes.to_vec();
    let diff = size % len;
    if diff > 0 {
        bytes.resize(len + diff, diff as u8);
    } else {
        bytes.resize(len + size, size as u8);
    }
    bytes
}

pub fn remove_padding(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 0 {
        return vec![];
    }
    let mut bytes = bytes.to_vec();
    let last_byte = *bytes.last().unwrap() as usize;
    bytes.truncate(bytes.len() - last_byte);
    bytes
}

#[cfg(test)]
mod tests {
    use super::pad_block;

    #[test]
    fn test_pad_block() {
        assert_eq!(
            &pad_block(b"YELLOW SUBMARINE", 20),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
        assert_eq!(
            &pad_block(b"YELLOW SUBMARINE", 12),
            b"YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08"
        );
        assert_eq!(
            &pad_block(b"YELLOW SUBMARINE", 16),
            b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10" // YELLOW SUBMARINE + 16 "16" bytes
        );
    }
}
