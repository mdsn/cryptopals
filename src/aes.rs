use aes::{
    cipher::generic_array::GenericArray,
    cipher::{consts::U16, KeyInit},
    Aes128,
};

pub const KEY_SIZE: usize = 16;

type Key = GenericArray<u8, U16>;
type Block = GenericArray<u8, U16>;

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
    bytes
        .chunks(16)
        .map(|b| make_block(b))
        .collect()
}