extern crate bls_signatures;
extern crate pairing;
extern crate rand;
extern crate rayon;

use std::time::{Duration, Instant};

use bls_signatures::*;
use pairing::bls12_381::G2;
use pairing::CurveProjective;
use rand::{Rng, SeedableRng, XorShiftRng};
use rayon::prelude::*;

fn main() {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let num_messages = 10_000;

    // generate private keys
    println!("creating keys");
    let private_keys: Vec<_> = (0..num_messages)
        .map(|_| PrivateKey::generate(rng))
        .collect();

    // generate messages
    let messages: Vec<Vec<u8>> = (0..num_messages)
        .map(|_| (0..64).map(|_| rng.gen()).collect())
        .collect();

    // sign messages
    println!("signing messages");
    let sigs = messages
        .par_iter()
        .zip(private_keys.par_iter())
        .map(|(message, pk)| pk.sign(message))
        .collect::<Vec<Signature>>();

    println!("aggregating signatures");
    let aggregated_signature = aggregate_signatures(&sigs);

    let hashes = messages
        .par_iter()
        .map(|message| G2::hash(message))
        .collect::<Vec<_>>();
    let public_keys = private_keys
        .par_iter()
        .map(|pk| pk.public_key())
        .collect::<Vec<_>>();

    println!("verifying aggregated signatures");
    let mut duration = Duration::new(0, 0);
    let start = Instant::now();

    assert!(verify(&aggregated_signature, &hashes, &public_keys));

    duration += start.elapsed();

    println!(
        "verification took {:?}s for {} signatures",
        duration.as_secs(),
        num_messages
    );
}
