use pairing::bls12_381::{Fr, FrRepr, G1Affine, G1};
use pairing::{CurveProjective, PrimeField, Wnaf};
use rand::Rng;

use super::signature::*;

pub struct PublicKey(G1);
pub struct PrivateKey(Fr);

impl From<G1> for PublicKey {
    fn from(val: G1) -> Self {
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

impl From<&PrivateKey> for FrRepr {
    fn from(val: &PrivateKey) -> Self {
        val.0.into_repr()
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

impl PublicKey {
    pub fn into_affine(&self) -> G1Affine {
        self.0.into_affine()
    }
}
