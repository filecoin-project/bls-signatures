use failure::Error;
use pairing::bls12_381::{Bls12, Fq12, G1Affine, G1Compressed, G2Affine, G1};
use pairing::{CurveAffine, CurveProjective, EncodedPoint, Engine, Field};
use rayon::prelude::*;

use super::key::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Signature(G1Affine);

impl From<G1> for Signature {
    fn from(val: G1) -> Self {
        Signature(val.into_affine())
    }
}

impl From<G1Affine> for Signature {
    fn from(val: G1Affine) -> Self {
        Signature(val)
    }
}

impl Signature {
    pub fn as_bytes(&self) -> Vec<u8> {
        G1Compressed::from_affine(self.0).as_ref().to_vec()
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != G1Compressed::size() {
            return Err(format_err!("size missmatch"));
        }

        let mut res = G1Compressed::empty();
        res.as_mut().copy_from_slice(raw);

        Ok(res.into_affine()?.into())
    }
}

/// Hash the given message, as used in the signature.
pub fn hash(msg: &[u8]) -> G1 {
    G1::hash(msg)
}

/// Aggregate signatures by multiplying them together.
/// Calculated by `signature = \sum_{i = 0}^n signature_i`.
pub fn aggregate(signatures: &[Signature]) -> Signature {
    let res = signatures
        .into_par_iter()
        .fold(
            || G1::zero(),
            |mut acc, signature| {
                acc.add_assign(&signature.0.into_projective());
                acc
            },
        )
        .reduce(
            || G1::zero(),
            |mut acc, val| {
                acc.add_assign(&val);
                acc
            },
        );

    Signature(res.into_affine())
}

/// Verifies that the signature is the actual aggregated signature of hashes - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
pub fn verify(signature: &Signature, hashes: &[G1], public_keys: &[PublicKey]) -> bool {
    assert_eq!(hashes.len(), public_keys.len());

    let mut prepared_keys = public_keys
        .par_iter()
        .map(|pk| pk.into_affine().prepare())
        .collect::<Vec<_>>();

    let mut g2_neg = G2Affine::one();
    g2_neg.negate();
    prepared_keys.push(g2_neg.prepare());

    let mut prepared_hashes = hashes
        .par_iter()
        .map(|h| h.into_affine().prepare())
        .collect::<Vec<_>>();
    prepared_hashes.push(signature.0.prepare());

    let prepared = prepared_hashes
        .iter()
        .zip(prepared_keys.iter())
        .collect::<Vec<_>>();

    Fq12::one() == Bls12::final_exponentiation(&Bls12::miller_loop(&prepared)).unwrap()
}

#[cfg(test)]
mod tests {
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

        let aggregated_signature = aggregate(&sigs);

        let hashes = messages
            .iter()
            .map(|message| G1::hash(message))
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

    #[test]
    fn test_bytes_roundtrip() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let sk = PrivateKey::generate(rng);

        let msg = (0..64).map(|_| rng.gen()).collect::<Vec<u8>>();
        let signature = sk.sign(&msg);

        let signature_bytes = signature.as_bytes();
        assert_eq!(signature_bytes.len(), 48);
        assert_eq!(Signature::from_bytes(&signature_bytes).unwrap(), signature);
    }
}
