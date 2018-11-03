#![feature(test)]

extern crate bls_signatures;
extern crate pairing;
extern crate rand;
extern crate test;

use self::test::Bencher;

use bls_signatures::*;
use rand::{Rng, SeedableRng, XorShiftRng};

#[bench]
fn bench_serialize_private_key_as_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let private_key = PrivateKey::generate(rng);

    b.iter(|| test::black_box(private_key.as_bytes()));
}

#[bench]
fn bench_serialize_private_key_from_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let private_key = PrivateKey::generate(rng);
    let bytes = private_key.as_bytes();

    b.iter(|| test::black_box(PrivateKey::from_bytes(&bytes).unwrap()));
}

#[bench]
fn bench_serialize_public_key_as_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let public_key = PrivateKey::generate(rng).public_key();

    b.iter(|| test::black_box(public_key.as_bytes()));
}

#[bench]
fn bench_serialize_public_key_from_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let public_key = PrivateKey::generate(rng).public_key();
    let bytes = public_key.as_bytes();

    b.iter(|| test::black_box(PublicKey::from_bytes(&bytes).unwrap()));
}

#[bench]
fn bench_serialize_signature_as_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let private_key = PrivateKey::generate(rng);
    let msg = (0..64).map(|_| rng.gen()).collect::<Vec<u8>>();
    let signature = private_key.sign(&msg);

    b.iter(|| test::black_box(signature.as_bytes()));
}

#[bench]
fn bench_serialize_signature_from_bytes(b: &mut Bencher) {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let private_key = PrivateKey::generate(rng);
    let msg = (0..64).map(|_| rng.gen()).collect::<Vec<u8>>();
    let signature = private_key.sign(&msg);
    let bytes = signature.as_bytes();

    b.iter(|| test::black_box(Signature::from_bytes(&bytes).unwrap()));
}
