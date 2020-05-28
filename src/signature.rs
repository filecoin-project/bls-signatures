use std::io;

use ff::Field;
use groupy::{CurveAffine, CurveProjective, EncodedPoint};
use paired::bls12_381::{Bls12, Fq12, G1Affine, G2Affine, G2Compressed, G2};
use paired::{Engine, ExpandMsgXmd, HashToCurve, PairingCurveAffine};
use rayon::prelude::*;

use crate::error::Error;
use crate::key::*;

const CSUITE: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Signature(G2Affine);

impl From<G2> for Signature {
    fn from(val: G2) -> Self {
        Signature(val.into_affine())
    }
}
impl From<Signature> for G2 {
    fn from(val: Signature) -> Self {
        val.0.into_projective()
    }
}

impl From<G2Affine> for Signature {
    fn from(val: G2Affine) -> Self {
        Signature(val)
    }
}

impl From<Signature> for G2Affine {
    fn from(val: Signature) -> Self {
        val.0
    }
}

impl Serialize for Signature {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        dest.write_all(G2Compressed::from_affine(self.0).as_ref())?;

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let g2 = g2_from_slice(raw)?;
        Ok(g2.into())
    }
}

fn g2_from_slice(raw: &[u8]) -> Result<G2Affine, Error> {
    if raw.len() != G2Compressed::size() {
        return Err(Error::SizeMismatch);
    }

    let mut res = G2Compressed::empty();
    res.as_mut().copy_from_slice(raw);

    Ok(res.into_affine()?)
}

/// Hash the given message, as used in the signature.
pub fn hash(msg: &[u8]) -> G2 {
    <G2 as HashToCurve<ExpandMsgXmd<sha2ni::Sha256>>>::hash_to_curve(msg, CSUITE)
}

/// Aggregate signatures by multiplying them together.
/// Calculated by `signature = \sum_{i = 0}^n signature_i`.
pub fn aggregate(signatures: &[Signature]) -> Signature {
    let res = signatures
        .into_par_iter()
        .fold(G2::zero, |mut acc, signature| {
            acc.add_assign(&signature.0.into_projective());
            acc
        })
        .reduce(G2::zero, |mut acc, val| {
            acc.add_assign(&val);
            acc
        });

    Signature(res.into_affine())
}

/// Verifies that the signature is the actual aggregated signature of hashes - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
pub fn verify(signature: &Signature, hashes: &[G2], public_keys: &[PublicKey]) -> bool {
    let n_hashes = hashes.len();

    if n_hashes == 0 {
        return false;
    }

    if n_hashes != public_keys.len() {
        return false;
    }

    // Enforce that messages are distinct as a countermeasure against BLS's rogue-key attack.
    // See Section 3.1. of the IRTF's BLS signatures spec:
    // https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
    for i in 0..(n_hashes - 1) {
        for j in (i + 1)..n_hashes {
            if hashes[i] == hashes[j] {
                return false;
            }
        }
    }

    let mut prepared: Vec<_> = public_keys
        .par_iter()
        .zip(hashes.par_iter())
        .map(|(pk, h)| (pk.as_affine().prepare(), h.into_affine().prepare()))
        .collect();

    let mut g1_neg = G1Affine::one();
    g1_neg.negate();
    prepared.push((g1_neg.prepare(), signature.0.prepare()));

    let prepared_refs = prepared.iter().map(|(a, b)| (a, b)).collect::<Vec<_>>();

    if let Some(res) = Bls12::final_exponentiation(&Bls12::miller_loop(&prepared_refs)) {
        Fq12::one() == res
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::STANDARD;
    use paired::bls12_381::{G1Compressed, G1};
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use serde::Deserialize;

    #[test]
    fn basic_aggregation() {
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let num_messages = 10;

        // generate private keys
        let private_keys: Vec<_> = (0..num_messages)
            .map(|_| PrivateKey::generate(&mut rng))
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
            .map(|message| hash(message))
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
    fn aggregation_same_messages() {
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let num_messages = 10;

        // generate private keys
        let private_keys: Vec<_> = (0..num_messages)
            .map(|_| PrivateKey::generate(&mut rng))
            .collect();

        // generate messages
        let message: Vec<u8> = (0..64).map(|_| rng.gen()).collect();

        // sign messages
        let sigs = private_keys
            .iter()
            .map(|pk| pk.sign(&message))
            .collect::<Vec<Signature>>();

        let aggregated_signature = aggregate(&sigs);

        // check that equal messages can not be aggreagated
        let hashes: Vec<_> = (0..num_messages).map(|_| hash(&message)).collect();
        let public_keys = private_keys
            .iter()
            .map(|pk| pk.public_key())
            .collect::<Vec<_>>();
        assert!(
            !verify(&aggregated_signature, &hashes, &public_keys),
            "must not verify aggregate with the same messages"
        );
    }

    #[test]
    fn test_bytes_roundtrip() {
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let sk = PrivateKey::generate(&mut rng);

        let msg = (0..64).map(|_| rng.gen()).collect::<Vec<u8>>();
        let signature = sk.sign(&msg);

        let signature_bytes = signature.as_bytes();
        assert_eq!(signature_bytes.len(), 96);
        assert_eq!(Signature::from_bytes(&signature_bytes).unwrap(), signature);
    }

    base64_serde_type!(Base64Standard, STANDARD);

    #[derive(Debug, Clone, Deserialize)]
    struct Case {
        #[serde(rename = "Msg")]
        msg: String,
        #[serde(rename = "Ciphersuite")]
        ciphersuite: String,
        #[serde(rename = "G1Compressed", with = "Base64Standard")]
        g1_compressed: Vec<u8>,
        #[serde(rename = "G2Compressed", with = "Base64Standard")]
        g2_compressed: Vec<u8>,
        #[serde(rename = "BLSPrivKey")]
        priv_key: Option<String>,
        #[serde(rename = "BLSPubKey")]
        pub_key: Option<String>,
        #[serde(rename = "BLSSigG2")]
        signature: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    struct Cases {
        cases: Vec<Case>,
    }

    fn g1_from_slice(raw: &[u8]) -> Result<G1Affine, Error> {
        if raw.len() != G1Compressed::size() {
            return Err(Error::SizeMismatch);
        }

        let mut res = G1Compressed::empty();
        res.as_mut().copy_from_slice(raw);

        Ok(res.into_affine()?)
    }

    #[test]
    fn test_vectors() {
        let cases: Cases =
            serde_json::from_slice(&std::fs::read("./tests/data.json").unwrap()).unwrap();

        for case in cases.cases {
            let g1: G1 = g1_from_slice(&case.g1_compressed)
                .unwrap()
                .into_projective();

            assert_eq!(
                g1,
                <G1 as HashToCurve<ExpandMsgXmd<sha2ni::Sha256>>>::hash_to_curve(
                    &case.msg,
                    case.ciphersuite.as_bytes()
                )
            );

            let g2: G2 = g2_from_slice(&case.g2_compressed)
                .unwrap()
                .into_projective();
            assert_eq!(
                g2,
                <G2 as HashToCurve<ExpandMsgXmd<sha2ni::Sha256>>>::hash_to_curve(
                    &case.msg,
                    case.ciphersuite.as_bytes()
                )
            );

            if case.ciphersuite.as_bytes() == CSUITE {
                let pub_key =
                    PublicKey::from_bytes(&base64::decode(case.pub_key.as_ref().unwrap()).unwrap())
                        .unwrap();
                let priv_key = PrivateKey::from_string(case.priv_key.as_ref().unwrap()).unwrap();
                let signature = Signature::from_bytes(
                    &base64::decode(case.signature.as_ref().unwrap()).unwrap(),
                )
                .unwrap();

                let sig2 = priv_key.sign(&case.msg);
                assert_eq!(signature, sig2, "signatures do not match");

                assert!(pub_key.verify(signature, &case.msg), "failed to verify");
            }
        }
    }
}
