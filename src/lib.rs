#[cfg(all(feature = "pairing", feature = "blst"))]
compile_error!("only pairing or blst can be enabled");

mod error;

#[cfg(feature = "min-sig")]
#[path="src/key_min_sig"] mod key;
#[cfg(not(feature = "min-sig"))]
mod key;

#[cfg(feature = "min-sig")]
#[path="src/signature_min_sig"] mod signature;
#[cfg(not(feature = "min-sig"))]
mod signature;

pub use self::error::Error;
pub use self::key::{PrivateKey, PublicKey, Serialize};
pub use self::signature::{aggregate, hash, verify, verify_messages, Signature};

#[cfg(test)]
#[macro_use]
extern crate base64_serde;
