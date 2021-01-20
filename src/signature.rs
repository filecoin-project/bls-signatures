use std::io;

use ff::Field;
use groupy::{CurveAffine, CurveProjective, EncodedPoint};
use rayon::prelude::*;

#[cfg(feature = "pairing")]
use paired::bls12_381::{Bls12, Fq12, G1Affine, G2Affine, G2Compressed, G2};
#[cfg(feature = "pairing")]
use paired::{Engine, ExpandMsgXmd, HashToCurve, PairingCurveAffine};

#[cfg(feature = "blst")]
use blstrs::{
    Bls12, Engine, Fp12 as Fq12, G1Affine, G2Affine, G2Compressed, G2Projective as G2,
    PairingCurveAffine,
};

use crate::error::Error;
use crate::key::*;

const CSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

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
#[cfg(feature = "pairing")]
pub fn hash(msg: &[u8]) -> G2 {
    <G2 as HashToCurve<ExpandMsgXmd<sha2ni::Sha256>>>::hash_to_curve(msg, CSUITE)
}

#[cfg(feature = "blst")]
pub fn hash(msg: &[u8]) -> G2 {
    G2::hash_to_curve(msg, CSUITE, &[])
}

/// Aggregate signatures by multiplying them together.
/// Calculated by `signature = \sum_{i = 0}^n signature_i`.
pub fn aggregate(signatures: &[Signature]) -> Result<Signature, Error> {
    if signatures.is_empty() {
        return Err(Error::ZeroSizedInput);
    }

    let res = signatures
        .into_par_iter()
        .fold(G2::zero, |mut acc, signature| {
            acc.add_assign_mixed(&signature.0);
            acc
        })
        .reduce(G2::zero, |mut acc, val| {
            acc.add_assign(&val);
            acc
        });

    Ok(Signature(res.into_affine()))
}

/// Verifies that the signature is the actual aggregated signature of hashes - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
pub fn verify(signature: &Signature, hashes: &[G2], public_keys: &[PublicKey]) -> bool {
    if hashes.is_empty() || public_keys.is_empty() {
        return false;
    }

    let n_hashes = hashes.len();

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

    let mut ml = public_keys
        .par_iter()
        .zip(hashes.par_iter())
        .map(|(pk, h)| {
            let pk = pk.as_affine().prepare();
            let h = h.into_affine().prepare();
            Bls12::miller_loop(&[(&pk, &h)])
        })
        .reduce(Fq12::one, |mut acc, cur| {
            acc.mul_assign(&cur);
            acc
        });

    let mut g1_neg = G1Affine::one();
    g1_neg.negate();
    ml.mul_assign(&Bls12::miller_loop(&[(
        &g1_neg.prepare(),
        &signature.0.prepare(),
    )]));

    if let Some(res) = Bls12::final_exponentiation(&ml) {
        Fq12::one() == res
    } else {
        false
    }
}

/// Verifies that the signature is the actual aggregated signature of messages - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
#[cfg(feature = "pairing")]
pub fn verify_messages(
    signature: &Signature,
    messages: &[&[u8]],
    public_keys: &[PublicKey],
) -> bool {
    let hashes: Vec<_> = messages.par_iter().map(|msg| hash(msg)).collect();
    verify(signature, &hashes, public_keys)
}

/// Verifies that the signature is the actual aggregated signature of messages - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
#[cfg(feature = "blst")]
pub fn verify_messages(
    signature: &Signature,
    messages: &[&[u8]],
    public_keys: &[PublicKey],
) -> bool {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    if messages.is_empty() || public_keys.is_empty() {
        return false;
    }

    let n_messages = messages.len();

    if n_messages != public_keys.len() {
        return false;
    }

    // Enforce that messages are distinct as a countermeasure against BLS's rogue-key attack.
    // See Section 3.1. of the IRTF's BLS signatures spec:
    // https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
    for i in 0..(n_messages - 1) {
        for j in (i + 1)..n_messages {
            if messages[i] == messages[j] {
                return false;
            }
        }
    }

    let (tx, rx) = crossbeam_channel::unbounded();
    let counter = AtomicUsize::new(0);
    let valid = AtomicBool::new(true);

    let n_workers = std::cmp::min(rayon::current_num_threads(), n_messages);

    rayon::scope(|s| {
        for _ in 0..n_workers {
            let tx = tx.clone();
            let counter = &counter;
            let valid = &valid;

            s.spawn(move |_| {
                let mut pairing = blstrs::PairingG1G2::new(true, CSUITE);

                while valid.load(Ordering::Relaxed) {
                    let work = counter.fetch_add(1, Ordering::Relaxed);
                    if work >= n_messages {
                        break;
                    }
                    let _res = pairing.aggregate(
                        &public_keys[work].0.into_affine(),
                        None,
                        &messages[work],
                        &[],
                    );

                    // Matches `blst@0.2.0`, not checking the errors.
                    // TODO: once upgrading to `blst@0.3`, uncomment.
                    // if res.is_err() {
                    //     valid.store(false, Ordering::Relaxed);
                    //     break;
                    // }
                }
                if valid.load(Ordering::Relaxed) {
                    pairing.commit();
                }
                tx.send(pairing).expect("channel gone");
            });
        }
    });

    let mut gtsig = Fq12::zero();
    if valid.load(Ordering::Relaxed) {
        blstrs::PairingG1G2::aggregated(&mut gtsig, &signature.0);
    }

    let mut acc = rx.recv().unwrap();
    for _ in 1..n_workers {
        let _res = acc.merge(&rx.recv().unwrap());
        // Matches `blst@0.2.0`, not checking the errors.
        // TODO: once upgrading to `blst@0.3`, uncomment.
        // if res.is_err() {
        //     return false;
        // }
    }

    if valid.load(Ordering::Relaxed) && acc.finalverify(Some(&gtsig)) {
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::STANDARD;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use serde::Deserialize;

    #[cfg(feature = "blst")]
    use blstrs::{G1Compressed, G1Projective as G1, Scalar as Fr};
    #[cfg(feature = "pairing")]
    use paired::bls12_381::{Fr, G1Compressed, G1};

    #[test]
    fn basic_aggregation() {
        let mut rng = ChaCha8Rng::seed_from_u64(12);

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

        let aggregated_signature = aggregate(&sigs).expect("failed to aggregate");

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

        let messages = messages.iter().map(|r| &r[..]).collect::<Vec<_>>();
        assert!(verify_messages(
            &aggregated_signature,
            &messages[..],
            &public_keys
        ));
    }

    #[test]
    fn aggregation_same_messages() {
        let mut rng = ChaCha8Rng::seed_from_u64(12);

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

        let aggregated_signature = aggregate(&sigs).expect("failed to aggregate");

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
        let messages = vec![&message[..]; num_messages];

        assert!(!verify_messages(
            &aggregated_signature,
            &messages[..],
            &public_keys
        ));
    }

    #[test]
    fn test_zero_key() {
        let mut rng = ChaCha8Rng::seed_from_u64(12);

        // In the current iteration we expect the zero key to be valid and work.
        let zero_key: PrivateKey = Fr::zero().into();
        assert!(zero_key.public_key().0.is_zero());

        println!(
            "{:?}\n{:?}",
            zero_key.public_key().as_bytes(),
            zero_key.as_bytes()
        );
        let num_messages = 10;

        // generate private keys
        let mut private_keys: Vec<_> = (0..num_messages - 1)
            .map(|_| PrivateKey::generate(&mut rng))
            .collect();

        private_keys.push(zero_key);

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

        let aggregated_signature = aggregate(&sigs).expect("failed to aggregate");

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

        let messages = messages.iter().map(|r| &r[..]).collect::<Vec<_>>();
        assert!(verify_messages(
            &aggregated_signature,
            &messages[..],
            &public_keys
        ));

        // single message is rejected
        let signature = zero_key.sign(&messages[0]);

        assert!(!zero_key.public_key().verify(signature, &messages[0]));
    }

    #[test]
    fn test_bytes_roundtrip() {
        let mut rng = ChaCha8Rng::seed_from_u64(12);
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

    #[cfg(feature = "pairing")]
    fn hash_to_g1(msg: &[u8], suite: &[u8]) -> G1 {
        <G1 as HashToCurve<ExpandMsgXmd<sha2ni::Sha256>>>::hash_to_curve(msg, suite)
    }
    #[cfg(feature = "blst")]
    fn hash_to_g1(msg: &[u8], suite: &[u8]) -> G1 {
        G1::hash_to_curve(msg, suite, &[])
    }

    #[cfg(feature = "pairing")]
    fn hash_to_g2(msg: &[u8], suite: &[u8]) -> G2 {
        <G2 as HashToCurve<ExpandMsgXmd<sha2ni::Sha256>>>::hash_to_curve(msg, suite)
    }
    #[cfg(feature = "blst")]
    fn hash_to_g2(msg: &[u8], suite: &[u8]) -> G2 {
        G2::hash_to_curve(msg, suite, &[])
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
                hash_to_g1(case.msg.as_bytes(), case.ciphersuite.as_bytes())
            );

            let g2: G2 = g2_from_slice(&case.g2_compressed)
                .unwrap()
                .into_projective();
            assert_eq!(
                g2,
                hash_to_g2(case.msg.as_bytes(), case.ciphersuite.as_bytes())
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
