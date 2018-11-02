#![feature(test)]

extern crate ff;
extern crate pairing;
extern crate rand;
extern crate test;

use pairing::bls12_381::{Bls12, Fr, G1Affine, G1, G2};
use pairing::{CurveAffine, CurveProjective, Engine, PrimeField, Wnaf};
use rand::Rng;

pub struct PrivateKey(Fr);
pub struct PublicKey(G1);
pub struct Signature(G2);

impl PrivateKey {
    /// Generate a new public - private key pair.
    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        PrivateKey(rng.gen())
    }

    /// Sign the given message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        // TODO: cache these
        // TODO: determine the right window size
        let g = G2::hash(message);
        let s = self.0.into_repr();

        // compute g * s
        let mut wnaf = Wnaf::new();
        Signature(wnaf.scalar(s).base(g))
    }

    pub fn public_key(&self) -> PublicKey {
        // TODO: cache?
        let s = self.0.into_repr();
        let mut wnaf = Wnaf::new();
        PublicKey(wnaf.scalar(s).base(G1::one()))
    }
}

/// Aggregate signatures by multiplying them together.
pub fn aggregate_signatures(signatures: &[Signature]) -> Signature {
    let mut res = G2::zero();
    for signature in signatures {
        res.add_assign(&signature.0);
    }

    Signature(res)
}

/// Verifies that the signature is the actual aggregated signature of hashes - pubkeys.
pub fn verify(signature: &Signature, hashes: &[G2], public_keys: &[PublicKey]) -> bool {
    assert_eq!(hashes.len(), public_keys.len());

    let lhs = G1Affine::one().pairing_with(&signature.0.into_affine());

    // TODO: investigate multithreading
    // TODO: implement full combination as chia does
    let prepared_keys = public_keys
        .iter()
        .map(|pk| pk.0.into_affine().prepare())
        .collect::<Vec<_>>();
    let prepared_hashes = hashes
        .iter()
        .map(|h| h.into_affine().prepare())
        .collect::<Vec<_>>();

    let prepared = prepared_keys
        .iter()
        .zip(prepared_hashes.iter())
        .collect::<Vec<_>>();

    let rhs = Bls12::final_exponentiation(&Bls12::miller_loop(&prepared)).unwrap();

    lhs == rhs
}

#[cfg(test)]
mod tests {
    use self::test::Bencher;
    use super::*;

    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn basic_aggregation() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let num_messages = 10;

        // generate private keys
        let private_keys: Vec<_> = (0..num_messages)
            .map(|_| PrivateKey::generate(rng))
            .collect();

        // generate messages
        let messages: Vec<Vec<u8>> = (0..num_messages)
            .map(|_| (0..64).map(|_| rng.gen()).collect())
            .collect();

        // sign messages
        let sigs = messages
            .iter()
            .zip(&private_keys)
            .map(|(message, pk)| pk.sign(message))
            .collect::<Vec<Signature>>();

        let aggregated_signature = aggregate_signatures(&sigs);

        let hashes = messages
            .iter()
            .map(|message| G2::hash(message))
            .collect::<Vec<_>>();
        let public_keys = private_keys
            .iter()
            .map(|pk| pk.public_key())
            .collect::<Vec<_>>();

        assert!(
            verify(&aggregated_signature, &hashes, &public_keys),
            "failed to verify"
        );
    }

    #[bench]
    fn bench_verify_100(b: &mut Bencher) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let num_messages = 100;

        // generate private keys
        let private_keys: Vec<_> = (0..num_messages)
            .map(|_| PrivateKey::generate(rng))
            .collect();

        // generate messages
        let messages: Vec<Vec<u8>> = (0..num_messages)
            .map(|_| (0..64).map(|_| rng.gen()).collect())
            .collect();

        // sign messages
        let sigs = messages
            .iter()
            .zip(&private_keys)
            .map(|(message, pk)| pk.sign(message))
            .collect::<Vec<Signature>>();

        let aggregated_signature = aggregate_signatures(&sigs);

        let hashes = messages
            .iter()
            .map(|message| G2::hash(message))
            .collect::<Vec<_>>();
        let public_keys = private_keys
            .iter()
            .map(|pk| pk.public_key())
            .collect::<Vec<_>>();

        b.iter(|| test::black_box(verify(&aggregated_signature, &hashes, &public_keys)))
    }
}
