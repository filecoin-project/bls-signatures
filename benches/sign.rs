#![feature(test)]

extern crate bls_signatures;
extern crate pairing;
extern crate rand;
extern crate test;

use self::test::Bencher;

use bls_signatures::*;
use rand::{Rng, SeedableRng, XorShiftRng};

#[bench]
fn sign_64b(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let private_key = PrivateKey::generate(rng);
    let msg: Vec<u8> = (0..64).map(|_| rng.gen()).collect();

    b.iter(|| test::black_box(private_key.sign(&msg)))
}
