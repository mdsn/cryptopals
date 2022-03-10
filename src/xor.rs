/// Xor two equally long byte slices.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len()); // TODO: ???
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}