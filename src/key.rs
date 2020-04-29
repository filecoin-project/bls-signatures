use std::io::{self, Cursor, Read};

use ff::{Field, PrimeField};
use groupy::{CurveAffine, CurveProjective, EncodedPoint};
use hkdf::Hkdf;
use paired::bls12_381::{Bls12, Fq12, Fr, FrRepr, G1Affine, G1Compressed, G2Affine, G1};
use paired::{BaseFromRO, Engine, PairingCurveAffine};
use rand_core::RngCore;
use sha2ni::digest::generic_array::typenum::U48;
use sha2ni::digest::generic_array::GenericArray;
use sha2ni::Sha256;

use crate::error::Error;
use crate::signature::*;

// "BLS-SIG-KEYGEN-SALT-"
const SALT: &[u8] = &[
    66, 76, 83, 45, 83, 73, 71, 45, 75, 69, 89, 71, 69, 78, 45, 83, 65, 76, 84, 45,
];

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PublicKey(G1);

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PrivateKey(Fr);

impl From<G1> for PublicKey {
    fn from(val: G1) -> Self {
        PublicKey(val)
    }
}
impl From<PublicKey> for G1 {
    fn from(val: PublicKey) -> Self {
        val.0
    }
}

impl From<Fr> for PrivateKey {
    fn from(val: Fr) -> Self {
        PrivateKey(val)
    }
}

impl From<PrivateKey> for Fr {
    fn from(val: PrivateKey) -> Self {
        val.0
    }
}
impl From<PrivateKey> for FrRepr {
    fn from(val: PrivateKey) -> Self {
        val.0.into_repr()
    }
}

impl<'a> From<&'a PrivateKey> for FrRepr {
    fn from(val: &'a PrivateKey) -> Self {
        val.0.into_repr()
    }
}

pub trait Serialize: ::std::fmt::Debug + Sized {
    /// Writes the key to the given writer.
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()>;

    /// Recreate the key from bytes in the same form as `write_bytes` produced.
    fn from_bytes(raw: &[u8]) -> Result<Self, Error>;

    fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(8 * 4);
        self.write_bytes(&mut res).expect("preallocated");
        res
    }
}

impl PrivateKey {
    /// Generate a deterministic private key from the given bytes.
    ///
    /// They must be at least 32 bytes long to be secure.
    pub fn new<T: AsRef<[u8]>>(msg: T) -> Self {
        PrivateKey(key_gen(msg))
    }

    /// Generate a new private key.
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        // IKM must be at least 32 bytes long:
        // https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-00#section-2.3
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        Self::new(ikm)
    }

    /// Sign the given message.
    /// Calculated by `signature = hash_into_g2(message) * sk`
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Signature {
        let mut p = hash(message.as_ref());
        p.mul_assign(self.0);

        p.into()
    }

    /// Get the public key for this private key.
    /// Calculated by `pk = g1 * sk`.
    pub fn public_key(&self) -> PublicKey {
        let mut pk = G1::one();
        pk.mul_assign(self.0);

        PublicKey(pk)
    }

    /// Deserializes a private key from the field element as a decimal number.
    pub fn from_string<T: AsRef<str>>(s: T) -> Result<Self, Error> {
        match Fr::from_str(s.as_ref()) {
            Some(f) => Ok(f.into()),
            None => Err(Error::InvalidPrivateKey),
        }
    }
}

impl Serialize for PrivateKey {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        for digit in self.0.into_repr().as_ref().iter() {
            dest.write_all(&digit.to_le_bytes())?;
        }

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let mut res = FrRepr::default();
        let mut reader = Cursor::new(raw);
        let mut buf = [0; 8];

        for digit in res.0.as_mut().iter_mut() {
            reader.read_exact(&mut buf)?;
            *digit = u64::from_le_bytes(buf);
        }

        Ok(Fr::from_repr(res)?.into())
    }
}

impl PublicKey {
    pub fn as_affine(&self) -> G1Affine {
        self.0.into_affine()
    }

    pub fn verify<T: AsRef<[u8]>>(&self, sig: Signature, message: T) -> bool {
        let p = hash(message.as_ref()).into_affine().prepare();
        let g1gen = {
            let mut tmp = G1::one();
            tmp.negate();
            tmp.into_affine().prepare()
        };

        let sig_affine: G2Affine = sig.into();
        match Bls12::final_exponentiation(&Bls12::miller_loop(&[
            (&self.0.into_affine().prepare(), &p),
            (&g1gen, &sig_affine.prepare()),
        ])) {
            None => false,
            Some(res) => res == Fq12::one(),
        }
    }
}

impl Serialize for PublicKey {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        let t = self.0.into_affine();
        let tmp = G1Compressed::from_affine(t);
        dest.write_all(tmp.as_ref())?;

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != G1Compressed::size() {
            return Err(Error::SizeMismatch);
        }

        let mut res = G1Compressed::empty();
        res.as_mut().copy_from_slice(raw);
        let affine = res.into_affine()?;

        Ok(PublicKey(affine.into_projective()))
    }
}

/// Hash a secret key sk to the secret exponent x'; then (PK, SK) = (g^{x'}, x').
fn key_gen<T: AsRef<[u8]>>(data: T) -> Fr {
    let mut result = GenericArray::<u8, U48>::default();

    // `result` has enough length to hold the output from HKDF expansion
    assert!(Hkdf::<Sha256>::new(Some(SALT), data.as_ref())
        .expand(&[], &mut result)
        .is_ok());
    Fr::from_okm(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_bytes_roundtrip() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let sk = PrivateKey::generate(rng);
        let sk_bytes = sk.as_bytes();

        assert_eq!(sk_bytes.len(), 32);
        assert_eq!(PrivateKey::from_bytes(&sk_bytes).unwrap(), sk);

        let pk = sk.public_key();
        let pk_bytes = pk.as_bytes();

        assert_eq!(pk_bytes.len(), 48);
        assert_eq!(PublicKey::from_bytes(&pk_bytes).unwrap(), pk);
    }

    #[test]
    fn test_key_gen() {
        let fr_val = key_gen("hello world (it's a secret!)");
        let expect = FrRepr([
            0x12760642e26dd0b2u64,
            0x577f0ddcee74cc5fu64,
            0xd6b63edfcad22ccu64,
            0x55b3719e3864a1acu64,
        ]);
        assert_eq!(fr_val, Fr::from_repr(expect).unwrap());
    }

    #[test]
    fn test_sig() {
        let msg = "this is the message";
        let sk = "this is the key";

        let sk = PrivateKey::new(sk);
        let sig = sk.sign(msg);
        let pk = sk.public_key();

        assert!(pk.verify(sig, msg));
    }
}
