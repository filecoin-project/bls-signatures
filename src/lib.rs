extern crate ff;
extern crate pairing;
extern crate rand;
extern crate rayon;

mod key;
mod signature;

pub use self::key::{PrivateKey, PublicKey};
pub use self::signature::{aggregate, hash, verify, Signature};
