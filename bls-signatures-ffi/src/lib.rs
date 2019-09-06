use std::slice::from_raw_parts;

use bls_signatures::{
    aggregate as aggregate_sig, hash as hash_sig,
    paired::bls12_381::G2Compressed,
    paired::{CurveAffine, CurveProjective, EncodedPoint},
    verify as verify_sig, PrivateKey, PublicKey, Serialize, Signature,
};
use libc;
use rand::OsRng;

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
    let digest = hash_sig(message);

    // prep response
    let mut raw_digest: [u8; DIGEST_BYTES] = [0; DIGEST_BYTES];
    raw_digest.copy_from_slice(digest.into_affine().into_compressed().as_ref());

    let response = responses::HashResponse { digest: raw_digest };

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
    let signatures: Vec<_> = from_raw_parts(flattened_signatures_ptr, flattened_signatures_len)
        .iter()
        .step_by(SIGNATURE_BYTES)
        .map(|item| {
            let sliced = from_raw_parts(item, SIGNATURE_BYTES);
            Signature::from_bytes(sliced).unwrap()
        })
        .collect();

    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];
    aggregate_sig(&signatures)
        .write_bytes(&mut raw_signature.as_mut())
        .expect("preallocated");

    let response = responses::AggregateResponse {
        signature: raw_signature,
    };

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

    let raw_digests = from_raw_parts(flattened_digests_ptr, flattened_digests_len);
    let raw_public_keys = from_raw_parts(flattened_public_keys_ptr, flattened_public_keys_len);

    assert_eq!(raw_digests.len() % DIGEST_BYTES, 0);
    assert_eq!(raw_public_keys.len() % PUBLIC_KEY_BYTES, 0);

    assert_eq!(
        raw_digests.len() / DIGEST_BYTES,
        raw_public_keys.len() / PUBLIC_KEY_BYTES
    );

    let digests: Vec<_> = raw_digests
        .iter()
        .step_by(DIGEST_BYTES)
        .map(|item| {
            let sliced = from_raw_parts(item, DIGEST_BYTES);
            let mut digest = G2Compressed::empty();
            digest.as_mut().copy_from_slice(sliced);

            digest
                .into_affine()
                .expect("invalid digest")
                .into_projective()
        })
        .collect();

    let public_keys: Vec<_> = raw_public_keys
        .iter()
        .step_by(PUBLIC_KEY_BYTES)
        .map(|item| {
            let sliced = from_raw_parts(item, PUBLIC_KEY_BYTES);
            PublicKey::from_bytes(sliced).expect("invalid key")
        })
        .collect();

    // call method
    let result = verify_sig(&signature, digests.as_slice(), public_keys.as_slice());

    // prep response
    let response = responses::VerifyResponse {
        result: result as u8,
    };

    Box::into_raw(Box::new(response))
}

/// Generate a new private key
///
/// # Arguments
///
/// * `raw_seed_ptr` - pointer to a seed byte array
#[no_mangle]
pub unsafe extern "C" fn private_key_generate() -> *mut responses::PrivateKeyGenerateResponse {
    let rng = &mut OsRng::new().expect("not enough randomness");

    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    PrivateKey::generate(rng)
        .write_bytes(&mut raw_private_key.as_mut())
        .expect("preallocated");

    let response = responses::PrivateKeyGenerateResponse {
        private_key: raw_private_key,
    };

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
    let private_key = PrivateKey::from_bytes(private_key_slice).expect("invalid private key");
    let message = from_raw_parts(message_ptr, message_len);

    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];
    PrivateKey::sign(&private_key, message)
        .write_bytes(&mut raw_signature.as_mut())
        .expect("preallocated");

    let response = responses::PrivateKeySignResponse {
        signature: raw_signature,
    };

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
    let private_key = PrivateKey::from_bytes(private_key_slice).expect("invalid private key");

    let mut raw_public_key: [u8; PUBLIC_KEY_BYTES] = [0; PUBLIC_KEY_BYTES];
    private_key
        .public_key()
        .write_bytes(&mut raw_public_key.as_mut())
        .expect("preallocated");

    let response = responses::PrivateKeyPublicKeyResponse {
        public_key: raw_public_key,
    };

    Box::into_raw(Box::new(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_verification() {
        unsafe {
            let private_key = (*private_key_generate()).private_key;
            let public_key = (*private_key_public_key(&private_key[0])).public_key;
            let message = "hello world".as_bytes();
            let digest = (*hash(&message[0], message.len())).digest;
            let signature =
                (*private_key_sign(&private_key[0], &message[0], message.len())).signature;
            let verified = (*verify(
                &signature[0],
                &digest[0],
                digest.len(),
                &public_key[0],
                public_key.len(),
            ))
            .result;

            assert_eq!(1, verified);

            let different_message = "bye world".as_bytes();
            let different_digest = (*hash(&different_message[0], different_message.len())).digest;
            let not_verified = (*verify(
                &signature[0],
                &different_digest[0],
                different_digest.len(),
                &public_key[0],
                public_key.len(),
            ))
            .result;

            assert_eq!(0, not_verified);
        }
    }
}
