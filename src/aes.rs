use aes::{
    cipher::{consts::U16, KeyInit},
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt},
    Aes128,
};

use crate::pad;

pub const KEY_SIZE: usize = 16;

type Key = GenericArray<u8, U16>;
pub type Block = GenericArray<u8, U16>;

fn make_key(bytes: &[u8]) -> Key {
    GenericArray::clone_from_slice(bytes)
}

pub fn make_cipher(key: &[u8]) -> Aes128 {
    let key = make_key(key);
    Aes128::new(&key)
}

pub fn make_block(bytes: &[u8]) -> Block {
    GenericArray::clone_from_slice(bytes)
}

pub fn into_blocks(bytes: &[u8]) -> Vec<Block> {
    bytes.chunks(16).map(|b| make_block(b)).collect()
}

pub fn encrypt_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = make_cipher(key);
    let bytes = pad::pad_block(&bytes, KEY_SIZE);
    let mut blocks = into_blocks(&bytes);
    cipher.encrypt_blocks(blocks.as_mut_slice());
    blocks.iter().cloned().flatten().collect()
}

pub fn decrypt_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = make_cipher(key);
    let mut blocks = into_blocks(bytes);
    cipher.decrypt_blocks(blocks.as_mut_slice());
    let blocks: Vec<u8> = blocks.iter().cloned().flatten().collect();
    pad::remove_padding(&blocks)
}

#[cfg(test)]
mod tests {
    use super::{decrypt_ecb, encrypt_ecb};
    #[test]
    fn test_encrypt_decrypt_ecb() {
        let key = b"YELLOW SUBMARINE";
        let pt = b"OSTENSIBLY, YES";
        let enc = encrypt_ecb(pt, key);
        let dec = decrypt_ecb(&enc, key);
        assert_eq!(dec, pt);

        let pt = b"YELLOW SUBMARINE";
        let enc = encrypt_ecb(pt, key);
        let dec = decrypt_ecb(&enc, key);
        assert_eq!(dec, pt);
    }
}
