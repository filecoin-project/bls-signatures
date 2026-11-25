#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

use bls_signatures::*;
use rand::RngExt;

#[bench]
fn sign_64b(b: &mut Bencher) {
    let rng = &mut rand::rng();

    let private_key = PrivateKey::generate(rng);
    let msg: Vec<u8> = (0..64).map(|_| rng.random()).collect();

    b.iter(|| black_box(private_key.sign(&msg)))
}
