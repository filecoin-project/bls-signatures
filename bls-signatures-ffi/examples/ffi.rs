#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/libbls_signatures.rs"));

unsafe fn key_verification() -> Result<(), Box<std::error::Error>> {
    let seed = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let private_key = (*private_key_generate(&seed[0])).private_key;
    let public_key = (*private_key_public_key(&private_key[0])).public_key;
    let message = "hello world".as_bytes();
    let digest = (*hash(&message[0], message.len())).digest;
    let signature = (*private_key_sign(&private_key[0], &message[0], message.len())).signature;
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

    Ok(())
}

fn main() {
    unsafe { key_verification().unwrap() };
}
