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
fn bench_serialize_private_key_as_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed(SEED);

    let private_key = PrivateKey::generate(rng);

    b.iter(|| black_box(private_key.as_bytes()));
}

#[bench]
fn bench_serialize_private_key_from_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed(SEED);

    let private_key = PrivateKey::generate(rng);
    let bytes = private_key.as_bytes();

    b.iter(|| black_box(PrivateKey::from_bytes(&bytes).unwrap()));
}

#[bench]
fn bench_serialize_public_key_as_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed(SEED);

    let public_key = PrivateKey::generate(rng).public_key();

    b.iter(|| black_box(public_key.as_bytes()));
}

#[bench]
fn bench_serialize_public_key_from_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed(SEED);

    let public_key = PrivateKey::generate(rng).public_key();
    let bytes = public_key.as_bytes();

    b.iter(|| black_box(PublicKey::from_bytes(&bytes).unwrap()));
}

#[bench]
fn bench_serialize_signature_as_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed(SEED);

    let private_key = PrivateKey::generate(rng);
    let msg = (0..64).map(|_| rng.gen()).collect::<Vec<u8>>();
    let signature = private_key.sign(&msg);

    b.iter(|| black_box(signature.as_bytes()));
}

#[bench]
fn bench_serialize_signature_from_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed(SEED);

    let private_key = PrivateKey::generate(rng);
    let msg = (0..64).map(|_| rng.gen()).collect::<Vec<u8>>();
    let signature = private_key.sign(&msg);
    let bytes = signature.as_bytes();

    b.iter(|| black_box(Signature::from_bytes(&bytes).unwrap()));
}
