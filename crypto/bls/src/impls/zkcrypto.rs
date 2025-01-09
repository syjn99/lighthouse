use crate::{
    generic_aggregate_public_key::TAggregatePublicKey,
    generic_aggregate_signature::TAggregateSignature,
    generic_public_key::{
        GenericPublicKey, TPublicKey, PUBLIC_KEY_BYTES_LEN, PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN,
    },
    generic_secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    generic_signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, Hash256, ZeroizeHash, INFINITY_PUBLIC_KEY, INFINITY_SIGNATURE,
};

/// Provides the externally-facing, core BLS types.
pub mod types {
    pub use super::verify_signature_sets;
    pub use super::AggregatePublicKey;
    pub use super::AggregateSignature;
    pub use super::PublicKey;
    pub use super::SecretKey;
    pub use super::Signature;
    pub use super::SignatureSet;
}

pub type SignatureSet<'a> = crate::generic_signature_set::GenericSignatureSet<
    'a,
    PublicKey,
    AggregatePublicKey,
    Signature,
    AggregateSignature,
>;

pub fn verify_signature_sets<'a>(
    _signature_sets: impl ExactSizeIterator<Item = &'a SignatureSet<'a>>,
) -> bool {
    panic!("implement me")
}

#[derive(Clone)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES_LEN]);

impl PublicKey {
    fn infinity() -> Self {
        Self(INFINITY_PUBLIC_KEY)
    }
}

impl TPublicKey for PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        panic!("implement me")
        // self.0
    }

    fn serialize_uncompressed(&self) -> [u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN] {
        panic!("implement me")
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        panic!("implement me")
        // let mut pubkey = Self::infinity();
        // pubkey.0[..].copy_from_slice(&bytes[0..PUBLIC_KEY_BYTES_LEN]);
        // Ok(pubkey)
    }

    fn deserialize_uncompressed(_: &[u8]) -> Result<Self, Error> {
        panic!("implement me")
    }
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        panic!("implement me")
        // self.0[..] == other.0[..]
    }
}

#[derive(Clone)]
pub struct AggregatePublicKey([u8; PUBLIC_KEY_BYTES_LEN]);

impl TAggregatePublicKey<PublicKey> for AggregatePublicKey {
    fn to_public_key(&self) -> GenericPublicKey<PublicKey> {
        panic!("implement me")
        // GenericPublicKey::from_point(PublicKey(self.0))
    }

    fn aggregate(_pubkeys: &[GenericPublicKey<PublicKey>]) -> Result<Self, Error> {
        panic!("implement me")
        // Ok(Self(INFINITY_PUBLIC_KEY))
    }
}

impl Eq for AggregatePublicKey {}

impl PartialEq for AggregatePublicKey {
    fn eq(&self, other: &Self) -> bool {
        panic!("implement me")
        // self.0[..] == other.0[..]
    }
}

#[derive(Clone)]
pub struct Signature([u8; SIGNATURE_BYTES_LEN]);

impl Signature {
    fn infinity() -> Self {
        panic!("implement me")
        // Self([0; SIGNATURE_BYTES_LEN])
    }
}

impl TSignature<PublicKey> for Signature {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        panic!("implement me")
        // self.0
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        panic!("implement me")
        // let mut signature = Self::infinity();
        // signature.0[..].copy_from_slice(&bytes[0..SIGNATURE_BYTES_LEN]);
        // Ok(signature)
    }

    fn verify(&self, _pubkey: &PublicKey, _msg: Hash256) -> bool {
        panic!("implement me")
        // true
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        panic!("implement me")
        // self.0[..] == other.0[..]
    }
}

impl Eq for Signature {}

impl std::hash::Hash for Signature {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        panic!("implement me")
        // self.0.hash(hasher);
    }
}

#[derive(Clone)]
pub struct AggregateSignature([u8; SIGNATURE_BYTES_LEN]);

impl AggregateSignature {
    fn infinity() -> Self {
        panic!("implement me")
        // Self(INFINITY_SIGNATURE)
    }
}

impl TAggregateSignature<PublicKey, AggregatePublicKey, Signature> for AggregateSignature {
    fn infinity() -> Self {
        panic!("implement me")
        // Self::infinity()
    }

    fn add_assign(&mut self, _other: &Signature) {
        panic!("implement me")
    }

    fn add_assign_aggregate(&mut self, _other: &Self) {
        panic!("implement me")
    }

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        panic!("implement me")
        // let mut bytes = [0; SIGNATURE_BYTES_LEN];

        // bytes[..].copy_from_slice(&self.0);

        // bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        panic!("implement me")
        // let mut key = [0; SIGNATURE_BYTES_LEN];

        // key[..].copy_from_slice(bytes);

        // Ok(Self(key))
    }

    fn fast_aggregate_verify(
        &self,
        _msg: Hash256,
        _pubkeys: &[&GenericPublicKey<PublicKey>],
    ) -> bool {
        panic!("implement me")
        // true
    }

    fn aggregate_verify(
        &self,
        _msgs: &[Hash256],
        _pubkeys: &[&GenericPublicKey<PublicKey>],
    ) -> bool {
        panic!("implement me")
        // true
    }
}

impl Eq for AggregateSignature {}

impl PartialEq for AggregateSignature {
    fn eq(&self, other: &Self) -> bool {
        panic!("implement me")
        // self.0[..] == other.0[..]
    }
}

#[derive(Clone)]
pub struct SecretKey([u8; SECRET_KEY_BYTES_LEN]);

impl TSecretKey<Signature, PublicKey> for SecretKey {
    fn random() -> Self {
        panic!("implement me")
        // Self([0; SECRET_KEY_BYTES_LEN])
    }

    fn public_key(&self) -> PublicKey {
        panic!("implement me")
        // PublicKey::infinity()
    }

    fn sign(&self, _msg: Hash256) -> Signature {
        panic!("implement me")
        // Signature::infinity()
    }

    fn serialize(&self) -> ZeroizeHash {
        panic!("implement me")
        // let mut bytes = [0; SECRET_KEY_BYTES_LEN];
        // bytes[..].copy_from_slice(&self.0[..]);
        // bytes.into()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        panic!("implement me")
        // let mut sk = Self::random();
        // sk.0[..].copy_from_slice(&bytes[0..SECRET_KEY_BYTES_LEN]);
        // Ok(sk)
    }
}
