extern crate bls_signatures;
extern crate pairing;
extern crate rand;
extern crate rayon;

use std::time::{Duration, Instant};

use bls_signatures::*;
use pairing::bls12_381::G2;
use rand::{Rng, SeedableRng, XorShiftRng};
use rayon::prelude::*;

macro_rules! measure {
    ($name:expr, $code:block) => {
        println!("\t{}", $name);
        let start = Instant::now();
        let mut duration = Duration::new(0, 0);

        $code;

        duration += start.elapsed();
        println!(
            "\t  took {}.{}s",
            duration.as_secs(),
            duration.subsec_millis()
        );
    };
}

fn main() {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let num_messages = 10_000;

    println!("dancing with {} messages", num_messages);

    // generate private keys
    let private_keys: Vec<_> = (0..num_messages)
        .map(|_| PrivateKey::generate(rng))
        .collect();

    // generate messages
    let messages: Vec<Vec<u8>> = (0..num_messages)
        .map(|_| (0..64).map(|_| rng.gen()).collect())
        .collect();

    // sign messages
    let sigs: Vec<Signature>;
    measure!("signing", {
        sigs = messages
            .par_iter()
            .zip(private_keys.par_iter())
            .map(|(message, pk)| pk.sign(message))
            .collect::<Vec<Signature>>();
    });

    let aggregated_signature: Signature;
    measure!("aggregate signatures", {
        aggregated_signature = aggregate(&sigs);
    });

    let serialized_signatures: Vec<_>;
    measure!("serialize signatures", {
        serialized_signatures = sigs.par_iter().map(|s| s.as_bytes()).collect();
    });

    let deserialized_signatures: Vec<_>;
    measure!("deserialize signatures", {
        deserialized_signatures = serialized_signatures
            .par_iter()
            .map(|s| Signature::from_bytes(s).unwrap())
            .collect();
    });

    assert_eq!(deserialized_signatures.len(), sigs.len());

    let hashes: Vec<G2>;
    measure!("hashing messages", {
        hashes = messages
            .par_iter()
            .map(|message| hash(message))
            .collect::<Vec<_>>();
    });
    let public_keys: Vec<PublicKey>;
    measure!("extracting public keys", {
        public_keys = private_keys
            .par_iter()
            .map(|pk| pk.public_key())
            .collect::<Vec<_>>();
    });

    measure!("verification", {
        assert!(verify(&aggregated_signature, &hashes, &public_keys));
    });
}
