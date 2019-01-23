use libc;

use rand::{SeedableRng, XorShiftRng};
use std::mem;
use std::slice::from_raw_parts;

use crate::key::{PrivateKey, PublicKey};
use crate::signature;
use crate::signature::Signature;

use pairing::bls12_381::{G2Compressed, G2};
use pairing::{CurveAffine, CurveProjective, EncodedPoint};

pub mod responses;

const SIGNATURE_BYTES: usize = 96;
const PRIVATE_KEY_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 48;
const DIGEST_BYTES: usize = 96;

type BLSSignature = [u8; SIGNATURE_BYTES];
type BLSPrivateKey = [u8; PRIVATE_KEY_BYTES];
type BLSPublicKey = [u8; PUBLIC_KEY_BYTES];
type BLSDigest = [u8; DIGEST_BYTES];

/// Compute the digest of a message
///
/// # Arguments
///
/// * `message_ptr` - pointer to a message byte array
/// * `message_len` - length of the byte array
#[no_mangle]
pub unsafe extern "C" fn hash(
    message_ptr: *const u8,
    message_len: libc::size_t,
) -> *mut responses::HashResponse {
    // prep request
    let message = from_raw_parts(message_ptr, message_len);

    // call method
    let digest = signature::hash(message);

    // prep response
    let mut raw_digest: [u8; DIGEST_BYTES] = [0; DIGEST_BYTES];
    let compressed_digest = digest.into_affine().into_compressed();
    let compressed_digest_slice = compressed_digest.as_ref();
    raw_digest.copy_from_slice(compressed_digest_slice);

    let response = responses::HashResponse { digest: raw_digest };

    mem::forget(&response);

    Box::into_raw(Box::new(response))
}

/// Aggregate signatures together into a new signature
///
/// # Arguments
///
/// * `flattened_signatures_ptr` - pointer to a byte array containing signatures
/// * `flattened_signatures_len` - length of the byte array (multiple of SIGNATURE_BYTES)
#[no_mangle]
pub unsafe extern "C" fn aggregate(
    flattened_signatures_ptr: *const u8,
    flattened_signatures_len: libc::size_t,
) -> *mut responses::AggregateResponse {
    // prep request
    let raw_signatures = from_raw_parts(flattened_signatures_ptr, flattened_signatures_len)
        .iter()
        .step_by(SIGNATURE_BYTES)
        .fold(Default::default(), |mut acc: Vec<BLSSignature>, item| {
            let sliced = from_raw_parts(item, SIGNATURE_BYTES);
            let mut x: BLSSignature = [0; SIGNATURE_BYTES];
            x.copy_from_slice(&sliced[..SIGNATURE_BYTES]);
            acc.push(x);
            acc
        });
    let mut signatures: Vec<Signature> = Default::default();

    for raw_signature in raw_signatures {
        signatures.push(Signature::from_bytes(&raw_signature).unwrap());
    }

    // call method
    let signature = signature::aggregate(signatures.as_slice());

    // prep response
    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];
    raw_signature.copy_from_slice(signature.as_bytes().as_slice());

    let response = responses::AggregateResponse {
        signature: raw_signature,
    };

    mem::forget(&response);

    Box::into_raw(Box::new(response))
}

/// Verify that a signature is the aggregated signature of hashes - pubkeys
/// WARNING: This function can panic if there are a different number of digests and keys
///
/// # Arguments
///
/// * `signature_ptr`             - pointer to a signature byte array (SIGNATURE_BYTES long)
/// * `flattened_digests_ptr`     - pointer to a byte array containing digests
/// * `flattened_digests_len`     - length of the byte array (multiple of DIGEST_BYTES)
/// * `flattened_public_keys_ptr` - pointer to a byte array containing public keys
/// * `flattened_public_keys_len` - length of the byte array (multiple of PUBLIC_KEY_BYTES)
#[no_mangle]
pub unsafe extern "C" fn verify(
    signature_ptr: *const u8,
    flattened_digests_ptr: *const u8,
    flattened_digests_len: libc::size_t,
    flattened_public_keys_ptr: *const u8,
    flattened_public_keys_len: libc::size_t,
) -> *mut responses::VerifyResponse {
    // prep request
    let raw_signature = from_raw_parts(signature_ptr, SIGNATURE_BYTES);
    let signature = Signature::from_bytes(raw_signature).unwrap();

    let raw_digests = from_raw_parts(flattened_digests_ptr, flattened_digests_len)
        .iter()
        .step_by(DIGEST_BYTES)
        .fold(Default::default(), |mut acc: Vec<BLSDigest>, item| {
            let sliced = from_raw_parts(item, DIGEST_BYTES);
            let mut x: BLSDigest = [0; DIGEST_BYTES];
            x.copy_from_slice(&sliced[..DIGEST_BYTES]);
            acc.push(x);
            acc
        });
    let mut digests: Vec<G2> = Default::default();

    for raw_digest in raw_digests {
        let mut digest = G2Compressed::empty();
        digest.as_mut().copy_from_slice(&raw_digest);
        digests.push(digest.into_affine().unwrap().into_projective());
    }

    let raw_public_keys = from_raw_parts(flattened_public_keys_ptr, flattened_public_keys_len)
        .iter()
        .step_by(PUBLIC_KEY_BYTES)
        .fold(Default::default(), |mut acc: Vec<BLSPublicKey>, item| {
            let sliced = from_raw_parts(item, PUBLIC_KEY_BYTES);
            let mut x: BLSPublicKey = [0; PUBLIC_KEY_BYTES];
            x.copy_from_slice(&sliced[..PUBLIC_KEY_BYTES]);
            acc.push(x);
            acc
        });
    let mut public_keys: Vec<PublicKey> = Default::default();

    for raw_public_key in raw_public_keys {
        public_keys.push(PublicKey::from_bytes(&raw_public_key).unwrap());
    }

    // call method
    let result = signature::verify(&signature, digests.as_slice(), public_keys.as_slice());

    // prep response
    let response = responses::VerifyResponse {
        result: result as u8,
    };

    mem::forget(&response);

    Box::into_raw(Box::new(response))
}

/// Generate a new private key
///
/// # Arguments
///
/// * `raw_seed_ptr` - pointer to a seed byte array
#[no_mangle]
pub unsafe extern "C" fn private_key_generate(
    raw_seed_ptr: *const u8,
) -> *mut responses::PrivateKeyGenerateResponse {
    let raw_seed_slice = from_raw_parts(raw_seed_ptr, 16);
    let mut raw_seed: [u8; 16] = [0; 16];
    raw_seed.copy_from_slice(raw_seed_slice);
    let seed = mem::transmute::<[u8; 16], [u32; 4]>(raw_seed);

    // @TODO not this
    // let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let rng = &mut XorShiftRng::from_seed(seed);

    // call method
    let private_key = PrivateKey::generate(rng);

    // prep response
    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    raw_private_key.copy_from_slice(private_key.as_bytes().as_slice());

    let response = responses::PrivateKeyGenerateResponse {
        private_key: raw_private_key,
    };

    mem::forget(&response);

    Box::into_raw(Box::new(response))
}

/// Sign a message with a private key and return the signature
///
/// # Arguments
///
/// * `raw_private_key_ptr` - pointer to a private key byte array
/// * `message_ptr` - pointer to a message byte array
/// * `message_len` - length of the byte array
#[no_mangle]
pub unsafe extern "C" fn private_key_sign(
    raw_private_key_ptr: *const u8,
    message_ptr: *const u8,
    message_len: libc::size_t,
) -> *mut responses::PrivateKeySignResponse {
    // prep request
    let private_key_slice = from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);
    let private_key = PrivateKey::from_bytes(private_key_slice).unwrap();
    let message = from_raw_parts(message_ptr, message_len);

    // call method
    let signature = PrivateKey::sign(&private_key, message);

    // prep response
    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];
    raw_signature.copy_from_slice(signature.as_bytes().as_slice());

    let response = responses::PrivateKeySignResponse {
        signature: raw_signature,
    };

    mem::forget(&response);

    Box::into_raw(Box::new(response))
}

/// Generate the public key for a private key
///
/// # Arguments
///
/// * `raw_private_key_ptr` - pointer to a private key byte array
#[no_mangle]
pub unsafe extern "C" fn private_key_public_key(
    raw_private_key_ptr: *const u8,
) -> *mut responses::PrivateKeyPublicKeyResponse {
    let private_key_slice = from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);
    let private_key = PrivateKey::from_bytes(private_key_slice).unwrap();

    let public_key = private_key.public_key();

    let mut raw_public_key: [u8; PUBLIC_KEY_BYTES] = [0; PUBLIC_KEY_BYTES];
    raw_public_key.copy_from_slice(public_key.as_bytes().as_slice());

    let response = responses::PrivateKeyPublicKeyResponse {
        public_key: raw_public_key,
    };

    mem::forget(&response);

    Box::into_raw(Box::new(response))
}
