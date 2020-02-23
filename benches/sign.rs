#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

use bls_signatures::*;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

const SEED: [u8; 16] = [
    0x3d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54,
];

#[bench]
fn sign_64b(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed(SEED);

    let private_key = PrivateKey::generate(rng);
    let msg: Vec<u8> = (0..64).map(|_| rng.gen()).collect();

    b.iter(|| black_box(private_key.sign(&msg)))
}
