use aes::{
    cipher::{consts::U16, KeyInit},
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt},
    Aes128,
};

use crate::pad;
use crate::xor::xor_bytes;

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

/// Make a GenericArray of size 16 out of a slice of bytes.
pub fn make_block(bytes: &[u8]) -> Block {
    GenericArray::clone_from_slice(bytes)
}

/// Break a slice of bytes into GenericArrays of size 16 that Aes128 can use.
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

pub fn encrypt_cbc(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = make_cipher(key);
    let bytes = pad::pad_block(&bytes, KEY_SIZE);
    let mut prev = iv.to_vec();
    let mut enc = Vec::new();
    for block in bytes.chunks(key.len()) {
        let block = xor_bytes(block, &prev);
        let mut block = make_block(&block);
        cipher.encrypt_block(&mut block);
        let mut block: Vec<u8> = block.iter().cloned().collect();
        prev = block.clone();
        enc.append(&mut block);
    }
    enc
}

pub fn decrypt_cbc(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = make_cipher(key);
    let mut prev = iv.to_vec();
    let mut dec = Vec::new();
    for block in bytes.chunks(KEY_SIZE) {
        let ct = block.clone().to_owned();
        // decrypt
        let mut block = make_block(block);
        cipher.decrypt_block(&mut block);
        // xor with prev
        let block: Vec<u8> = block.iter().cloned().collect();
        let mut block = xor_bytes(&block, &prev);
        // prev <- ct clone
        dec.append(&mut block);
        prev = ct;
    }
    dec
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
