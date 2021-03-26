mod error;
mod key;
mod signature;

pub use self::error::Error;
pub use self::key::{PrivateKey, PublicKey, Serialize};
pub use self::signature::{aggregate, hash, verify, verify_messages, Signature};

#[cfg(test)]
#[macro_use]
extern crate base64_serde;
