use std::io::{self, Cursor};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use failure::{format_err, Error};
use ff::PrimeField;
use pairing::bls12_381::{Fr, FrRepr, G1Affine, G1Compressed, G1};
use pairing::{CurveProjective, EncodedPoint, Wnaf};
use rand::Rng;

use super::signature::*;

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey(G1Affine);

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey(Fr);

impl From<G1> for PublicKey {
    fn from(val: G1) -> Self {
        PublicKey(val.into_affine())
    }
}

impl From<G1Affine> for PublicKey {
    fn from(val: G1Affine) -> Self {
        PublicKey(val)
    }
}

impl From<Fr> for PrivateKey {
    fn from(val: Fr) -> Self {
        PrivateKey(val)
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
    /// Generate a new private key.
    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        // TODO: probably some better way to derive than just a random field element, but maybe
        // this is enough?
        let key: Fr = rng.gen();

        key.into()
    }

    /// Sign the given message.
    /// Calculated by `signature = hash_into_g2(message) * sk`
    pub fn sign(&self, message: &[u8]) -> Signature {
        // TODO: cache these
        let g = hash(message);

        // compute g * sk
        Wnaf::new().scalar(self.into()).base(g).into()
    }

    /// Get the public key for this private key.
    /// Calculated by `pk = g1 * sk`.
    pub fn public_key(&self) -> PublicKey {
        Wnaf::new().scalar(self.into()).base(G1::one()).into()
    }
}

impl Serialize for PrivateKey {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        for digit in self.0.into_repr().as_ref().iter() {
            dest.write_u64::<LittleEndian>(*digit)?;
        }

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let mut res = FrRepr::default();
        let mut reader = Cursor::new(raw);
        for digit in res.0.as_mut().iter_mut() {
            *digit = reader.read_u64::<LittleEndian>()?;
        }

        Ok(Fr::from_repr(res)?.into())
    }
}

impl PublicKey {
    pub fn as_affine(&self) -> G1Affine {
        self.0
    }
}

impl Serialize for PublicKey {
    fn write_bytes(&self, dest: &mut impl io::Write) -> io::Result<()> {
        dest.write_all(G1Compressed::from_affine(self.0).as_ref())?;

        Ok(())
    }

    fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != G1Compressed::size() {
            return Err(format_err!("size missmatch"));
        }

        let mut res = G1Compressed::empty();
        res.as_mut().copy_from_slice(raw);

        Ok(res.into_affine()?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{SeedableRng, XorShiftRng};

    #[test]
    fn test_bytes_roundtrip() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let sk = PrivateKey::generate(rng);
        let sk_bytes = sk.as_bytes();

        assert_eq!(sk_bytes.len(), 32);
        assert_eq!(PrivateKey::from_bytes(&sk_bytes).unwrap(), sk);

        let pk = sk.public_key();
        let pk_bytes = pk.as_bytes();

        assert_eq!(pk_bytes.len(), 48);
        assert_eq!(PublicKey::from_bytes(&pk_bytes).unwrap(), pk);
    }
}
