#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

use bls_signatures::*;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

const SEED: [u8; 16] = [
    0x3d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54,
];

macro_rules! bench_verify {
    ($name:ident, $num:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let rng = &mut XorShiftRng::from_seed(SEED);
            // generate private keys
            let private_keys: Vec<_> = (0..$num).map(|_| PrivateKey::generate(rng)).collect();

            // generate messages
            let messages: Vec<Vec<u8>> = (0..$num)
                .map(|_| (0..64).map(|_| rng.gen()).collect())
                .collect();

            // sign messages
            let sigs = messages
                .iter()
                .zip(&private_keys)
                .map(|(message, pk)| pk.sign(message))
                .collect::<Vec<Signature>>();

            let aggregated_signature = aggregate(&sigs);

            let hashes = messages
                .iter()
                .map(|message| hash(message))
                .collect::<Vec<_>>();
            let public_keys = private_keys
                .iter()
                .map(|pk| pk.public_key())
                .collect::<Vec<_>>();

            b.iter(|| black_box(verify(&aggregated_signature, &hashes, &public_keys)))
        }
    };
}

bench_verify!(bench_verify_1, 1);
bench_verify!(bench_verify_10, 10);
bench_verify!(bench_verify_100, 100);
