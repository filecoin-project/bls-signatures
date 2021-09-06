use std::slice::from_raw_parts;

#[cfg(feature = "pairing")]
use bls12_381::{G2Affine, G2Projective};
use bls_signatures::{
    aggregate as aggregate_sig, hash as hash_sig, verify as verify_sig,
    verify_messages as verify_messages_sig, Error, PrivateKey, PublicKey, Serialize, Signature,
};
#[cfg(feature = "blst")]
use blstrs::{G2Affine, G2Projective};
use group::GroupEncoding;
use rand::rngs::OsRng;
#[cfg(feature = "multicore")]
use rayon::prelude::*;

pub mod responses;

const SIGNATURE_BYTES: usize = 96;
const PRIVATE_KEY_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 48;
const DIGEST_BYTES: usize = 96;
const G2_COMPRESSED_SIZE: usize = 96;

type BLSSignature = [u8; SIGNATURE_BYTES];
type BLSPrivateKey = [u8; PRIVATE_KEY_BYTES];
type BLSPublicKey = [u8; PUBLIC_KEY_BYTES];
type BLSDigest = [u8; DIGEST_BYTES];

/// Unwraps or returns the passed in value.
macro_rules! try_ffi {
    ($res:expr, $val:expr) => {{
        match $res {
            Ok(res) => res,
            Err(_) => return $val,
        }
    }};
}

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
    raw_digest.copy_from_slice(digest.to_bytes().as_ref());

    let response = responses::HashResponse { digest: raw_digest };

    Box::into_raw(Box::new(response))
}

/// Aggregate signatures together into a new signature
///
/// # Arguments
///
/// * `flattened_signatures_ptr` - pointer to a byte array containing signatures
/// * `flattened_signatures_len` - length of the byte array (multiple of SIGNATURE_BYTES)
///
/// Returns `NULL` on error. Result must be freed using `destroy_aggregate_response`.
#[no_mangle]
pub unsafe extern "C" fn aggregate(
    flattened_signatures_ptr: *const u8,
    flattened_signatures_len: libc::size_t,
) -> *mut responses::AggregateResponse {
    // prep request

    #[cfg(feature = "multicore")]
    let parts = from_raw_parts(flattened_signatures_ptr, flattened_signatures_len)
        .par_chunks(SIGNATURE_BYTES);
    #[cfg(not(feature = "multicore"))]
    let parts =
        from_raw_parts(flattened_signatures_ptr, flattened_signatures_len).chunks(SIGNATURE_BYTES);

    let signatures = try_ffi!(
        parts
            .map(|item| Signature::from_bytes(item))
            .collect::<Result<Vec<_>, _>>(),
        std::ptr::null_mut()
    );

    let mut raw_signature: [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];
    try_ffi!(aggregate_sig(&signatures), std::ptr::null_mut())
        .write_bytes(&mut raw_signature.as_mut())
        .expect("preallocated");

    let response = responses::AggregateResponse {
        signature: raw_signature,
    };

    Box::into_raw(Box::new(response))
}

/// Verify that a signature is the aggregated signature of hashes - pubkeys
///
/// # Arguments
///
/// * `signature_ptr`             - pointer to a signature byte array (SIGNATURE_BYTES long)
/// * `flattened_digests_ptr`     - pointer to a byte array containing digests
/// * `flattened_digests_len`     - length of the byte array (multiple of DIGEST_BYTES)
/// * `flattened_public_keys_ptr` - pointer to a byte array containing public keys
#[no_mangle]
pub unsafe extern "C" fn verify(
    signature_ptr: *const u8,
    flattened_digests_ptr: *const u8,
    flattened_digests_len: libc::size_t,
    flattened_public_keys_ptr: *const u8,
    flattened_public_keys_len: libc::size_t,
) -> libc::c_int {
    // prep request
    let raw_signature = from_raw_parts(signature_ptr, SIGNATURE_BYTES);
    let signature = try_ffi!(Signature::from_bytes(raw_signature), 0);

    let raw_digests = from_raw_parts(flattened_digests_ptr, flattened_digests_len);
    let raw_public_keys = from_raw_parts(flattened_public_keys_ptr, flattened_public_keys_len);

    if raw_digests.len() % DIGEST_BYTES != 0 {
        return 0;
    }
    if raw_public_keys.len() % PUBLIC_KEY_BYTES != 0 {
        return 0;
    }

    if raw_digests.len() / DIGEST_BYTES != raw_public_keys.len() / PUBLIC_KEY_BYTES {
        return 0;
    }

    #[cfg(feature = "multicore")]
    let raw = raw_digests.par_chunks(DIGEST_BYTES);
    #[cfg(not(feature = "multicore"))]
    let raw = raw_digests.chunks(DIGEST_BYTES);

    let digests: Vec<_> = try_ffi!(
        raw.map(|item: &[u8]| -> Result<G2Projective, Error> {
            let mut digest = [0u8; G2_COMPRESSED_SIZE];
            digest.as_mut().copy_from_slice(item);

            let affine: Option<G2Affine> = Option::from(G2Affine::from_compressed(&digest));
            affine.map(Into::into).ok_or(Error::CurveDecode)
        })
        .collect::<Result<Vec<G2Projective>, Error>>(),
        0
    );

    #[cfg(feature = "multicore")]
    let raw = raw_public_keys.par_chunks(PUBLIC_KEY_BYTES);
    #[cfg(not(feature = "multicore"))]
    let raw = raw_public_keys.chunks(PUBLIC_KEY_BYTES);

    let public_keys: Vec<_> = try_ffi!(
        raw.map(|item| { PublicKey::from_bytes(item) })
            .collect::<Result<_, _>>(),
        0
    );

    verify_sig(&signature, digests.as_slice(), public_keys.as_slice()) as libc::c_int
}

/// Verify that a signature is the aggregated signature of the given messages - pubkeys
///
/// # Arguments
///
/// * `signature_ptr`             - pointer to a signature byte array (SIGNATURE_BYTES long)
/// * `flattened_messages_ptr`    - pointer to a byte array containing all messages
/// * `flattened_messages_len`    - length of the byte array
/// * `messages_sizes_ptr`        - pointer to an array containing the lengths of the messages
/// * `messages_len`              - length of the two messages arrays
/// * `flattened_public_keys_ptr` - pointer to a byte array containing public keys
#[no_mangle]
pub unsafe extern "C" fn verify_messages(
    signature_ptr: *const u8,
    flattened_messages_ptr: *const u8,
    flattened_messages_len: libc::size_t,
    message_sizes_ptr: *const libc::size_t,
    message_sizes_len: libc::size_t,
    flattened_public_keys_ptr: *const u8,
    flattened_public_keys_len: libc::size_t,
) -> libc::c_int {
    // prep request
    let raw_signature = from_raw_parts(signature_ptr, SIGNATURE_BYTES);
    let signature = try_ffi!(Signature::from_bytes(raw_signature), 0);

    let flattened = from_raw_parts(flattened_messages_ptr, flattened_messages_len);
    let raw_public_keys = from_raw_parts(flattened_public_keys_ptr, flattened_public_keys_len);
    let chunk_sizes = from_raw_parts(message_sizes_ptr, message_sizes_len);

    // split the flattened message array into slices of individual messages to
    // be hashed
    let mut messages: Vec<&[u8]> = Vec::with_capacity(message_sizes_len);
    let mut offset = 0;
    for chunk_size in chunk_sizes.iter() {
        messages.push(&flattened[offset..offset + *chunk_size]);
        offset += *chunk_size
    }

    if raw_public_keys.len() % PUBLIC_KEY_BYTES != 0 {
        return 0;
    }

    if messages.len() != raw_public_keys.len() / PUBLIC_KEY_BYTES {
        return 0;
    }

    #[cfg(feature = "multicore")]
    let raw = raw_public_keys.par_chunks(PUBLIC_KEY_BYTES);
    #[cfg(not(feature = "multicore"))]
    let raw = raw_public_keys.chunks(PUBLIC_KEY_BYTES);

    let public_keys: Vec<_> = try_ffi!(
        raw.map(|item| { PublicKey::from_bytes(item) })
            .collect::<Result<_, _>>(),
        0
    );

    verify_messages_sig(&signature, &messages, public_keys.as_slice()) as libc::c_int
}

/// Generate a new private key
///
/// # Arguments
///
/// * `raw_seed_ptr` - pointer to a seed byte array
#[no_mangle]
pub unsafe extern "C" fn private_key_generate() -> *mut responses::PrivateKeyGenerateResponse {
    let mut raw_private_key: [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
    PrivateKey::generate(&mut OsRng)
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
///
/// Returns `NULL` when passed invalid arguments.
#[no_mangle]
pub unsafe extern "C" fn private_key_sign(
    raw_private_key_ptr: *const u8,
    message_ptr: *const u8,
    message_len: libc::size_t,
) -> *mut responses::PrivateKeySignResponse {
    // prep request
    let private_key_slice = from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);
    let private_key = try_ffi!(
        PrivateKey::from_bytes(private_key_slice),
        std::ptr::null_mut()
    );
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
///
/// Returns `NULL` when passed invalid arguments.
#[no_mangle]
pub unsafe extern "C" fn private_key_public_key(
    raw_private_key_ptr: *const u8,
) -> *mut responses::PrivateKeyPublicKeyResponse {
    let private_key_slice = from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);
    let private_key = try_ffi!(
        PrivateKey::from_bytes(private_key_slice),
        std::ptr::null_mut()
    );

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
            let message = b"hello world";
            let digest = (*hash(&message[0], message.len())).digest;
            let signature =
                (*private_key_sign(&private_key[0], &message[0], message.len())).signature;
            let verified = verify(
                &signature[0],
                &digest[0],
                digest.len(),
                &public_key[0],
                public_key.len(),
            );

            assert_eq!(1, verified);

            let message_sizes = [message.len()];
            let verified2 = verify_messages(
                signature.as_ptr(),
                message.as_ptr(),
                message.len(),
                message_sizes.as_ptr(),
                message_sizes.len(),
                public_key.as_ptr(),
                public_key.len(),
            );
            assert_eq!(1, verified2);

            let different_message = b"bye world";
            let different_digest = (*hash(&different_message[0], different_message.len())).digest;
            let not_verified = verify(
                &signature[0],
                &different_digest[0],
                different_digest.len(),
                &public_key[0],
                public_key.len(),
            );

            assert_eq!(0, not_verified);

            // garbage verification
            let different_digest = vec![0, 1, 2, 3, 4];
            let not_verified = verify(
                &signature[0],
                &different_digest[0],
                different_digest.len(),
                &public_key[0],
                public_key.len(),
            );

            assert_eq!(0, not_verified);
        }
    }
}
