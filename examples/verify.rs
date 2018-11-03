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
        let total =
            { f64::from(duration.subsec_nanos()) / 1_000_000_000f64 + (duration.as_secs() as f64) };

        println!("\t  took {:.6}s", total);
    };
    ($name:expr, $num:expr, $code:block) => {
        println!("\t{}", $name);
        let start = Instant::now();
        let mut duration = Duration::new(0, 0);

        $code;

        duration += start.elapsed();

        let total =
            { f64::from(duration.subsec_nanos()) / 1_000_000_000f64 + (duration.as_secs() as f64) };
        let per_msg = {
            let avg = duration / $num as u32;
            f64::from(avg.subsec_nanos()) / 1_000_000f64 + (avg.as_secs() as f64 * 1000f64)
        };

        println!("\t  took {:.6}s ({:.3}ms per message)", total, per_msg);
    };
}

fn run(num_messages: usize) {
    println!("dancing with {} messages", num_messages);

    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

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
    measure!("signing", num_messages, {
        sigs = messages
            .par_iter()
            .zip(private_keys.par_iter())
            .map(|(message, pk)| pk.sign(message))
            .collect::<Vec<Signature>>();
    });

    let aggregated_signature: Signature;
    measure!("aggregate signatures", num_messages, {
        aggregated_signature = aggregate(&sigs);
    });

    let serialized_signature: Vec<_>;
    measure!("serialize signature", {
        serialized_signature = aggregated_signature.as_bytes();
    });

    let hashes: Vec<G2>;
    measure!("hashing messages", num_messages, {
        hashes = messages
            .par_iter()
            .map(|message| hash(message))
            .collect::<Vec<_>>();
    });
    let public_keys: Vec<PublicKey>;
    measure!("extracting public keys", num_messages, {
        public_keys = private_keys
            .par_iter()
            .map(|pk| pk.public_key())
            .collect::<Vec<_>>();
    });

    let agg_sig: Signature;
    measure!("deserialize signature", {
        agg_sig = Signature::from_bytes(&serialized_signature).unwrap();
    });

    measure!("verification", num_messages, {
        assert!(verify(&agg_sig, &hashes, &public_keys));
    });
}

fn main() {
    run(10_000);
}
