/// xoshiro256** implementation
/// https://prng.di.unimi.it/

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = add(self.state, 0x9e3779b97f4a7c15_u64);

        let x = self.state;
        let mut z = x;
        z = mul(z ^ (z >> 30), 0xbf58476d1ce4e5b9_u64);
        z = mul(z ^ (z >> 27), 0x94d049bb133111eb_u64);
        z ^ (z >> 31)
    }
}

pub struct Xoshiro256 {
    state: [u64; 4],
}

// Overflowing multiplication of u64
#[inline]
fn mul(a: u64, b: u64) -> u64 {
    a.overflowing_mul(b).0
}

// Overflowing add of u64
#[inline]
fn add(a: u64, b: u64) -> u64 {
    a.overflowing_add(b).0
}

fn rotl(x: u64, k: i32) -> u64 {
    (x << k) | (x >> (64 - k))
}

impl Xoshiro256 {
    pub fn new(seed: u64) -> Self {
        let mut mix = SplitMix64::new(seed);
        let state = [mix.next(), mix.next(), mix.next(), mix.next()];
        Xoshiro256 { state }
    }

    pub fn next_num(&mut self) -> u64 {
        let res = mul(rotl(mul(self.state[1], 5), 7), 9);
        let t = self.state[1] << 17;

        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];

        self.state[2] ^= t;

        self.state[3] = rotl(self.state[3], 45);

        res
    }

    pub fn get_bytes(&mut self, n: u64) -> Vec<u8> {
        (0..n).map(|_| self.next_num() as u8).collect()
    }

    // Random number in the range [0..range)
    // https://www.pcg-random.org/posts/bounded-rands.html
    pub fn range(&mut self, mut range: u64) -> u64 {
        let mut mask: u64 = !0;
        range -= 1;
        mask >>= (range | 1).leading_zeros();
        let mut x: u64;
        loop {
            x = self.next_num() & mask;
            if x <= range {
                break;
            }
        }
        x
    }

    // Random boolean
    pub fn bool(&mut self) -> bool {
        self.range(2) == 1
    }
}

fn make_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

pub fn make_prng() -> Xoshiro256 {
    Xoshiro256::new(make_seed())
}

pub fn bytes(n: u64) -> Vec<u8> {
    let mut prng = make_prng();
    prng.get_bytes(n)
}

#[cfg(test)]
mod tests {
    use super::{SplitMix64, Xoshiro256};

    #[test]
    fn test_splitmix64() {
        let seed = 54321u64;
        let mut mix = SplitMix64::new(seed);
        for _ in 0..5 {
            println!("{}", mix.next());
        }
    }

    #[test]
    fn test_xoshiro256ss() {
        // test vectors: https://github.com/Quuxplusone/Xoshiro256ss
        let mut prng = Xoshiro256::new(100u64);
        let numbers: Vec<u64> = (0..4).map(|_| prng.next_num()).collect();
        assert_eq!(
            numbers,
            vec![
                792317387143481937u64,
                1418856489092323125u64,
                6662743737787356053u64,
                9823178768685107703u64
            ]
        );
    }

    #[test]
    fn test_range() {
        const LIMIT: u64 = 25;
        let mut prng = Xoshiro256::new(12345u64);
        let numbers: Vec<u64> = (0..50).map(|_| prng.range(LIMIT)).collect();
        assert!(numbers.iter().all(|n| n < &LIMIT));
    }
}
