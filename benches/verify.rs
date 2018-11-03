#![feature(test)]

extern crate bls_signatures;
extern crate pairing;
extern crate rand;
extern crate test;

use self::test::Bencher;

use bls_signatures::*;
use rand::{Rng, SeedableRng, XorShiftRng};

macro_rules! bench_verify {
    ($name:ident, $num:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
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

            b.iter(|| test::black_box(verify(&aggregated_signature, &hashes, &public_keys)))
        }
    };
}

bench_verify!(bench_verify_1, 1);
bench_verify!(bench_verify_10, 10);
bench_verify!(bench_verify_100, 100);
