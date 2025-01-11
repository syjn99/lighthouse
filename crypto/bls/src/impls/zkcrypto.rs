use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar,
};
use rand::{thread_rng, RngCore};

use crate::{
    generic_aggregate_public_key::TAggregatePublicKey,
    generic_aggregate_signature::TAggregateSignature,
    generic_public_key::{
        GenericPublicKey, TPublicKey, PUBLIC_KEY_BYTES_LEN, PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN,
    },
    generic_secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    generic_signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, Hash256, ZeroizeHash,
};

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

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

// See https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
pub fn verify_signature_sets<'a>(
    signature_sets: impl ExactSizeIterator<Item = &'a SignatureSet<'a>>,
) -> bool {
    let sets = signature_sets.collect::<Vec<_>>();

    if sets.is_empty() {
        return false;
    }

    let rng = &mut rand::thread_rng();

    // Generate random scalars for each set
    // We can use `Scalar::random`, but `ff` crate must be imported.
    let mut rands: Vec<Scalar> = Vec::with_capacity(sets.len());
    for _ in 0..sets.len() {
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        rands.push(Scalar::from_bytes_wide(&buf));
    }

    // e(g1, S*) = Π(e(P_{i,j}, M'_{i,j})) where:
    // S* = Σ(S_i * r_i)
    // M'_{i,j} = M_{i,j} * r_i
    let mut agg_sig = G2Projective::identity();
    let mut rhs = pairing(&G1Affine::generator(), &G2Affine::identity());

    for (set, rand) in sets.iter().zip(rands.iter()) {
        // Verify signature point exists and is in correct subgroup
        let Some(sig_point) = set.signature.point() else {
            return false;
        };
        if !bool::from(G2Affine::from(sig_point.0).is_torsion_free()) {
            return false;
        }

        // Verify we have signing keys
        if set.signing_keys.is_empty() {
            return false;
        }

        // Hash the message for this set: M_{i,j}
        let h = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
            &[set.message],
            DST,
        );

        // Aggregate public keys: P_{i,j}
        let agg_pk = set
            .signing_keys
            .iter()
            .fold(G1Projective::identity(), |acc, pk| acc + pk.point().0);

        // Add to accumulators using random weight:
        // S* += S_i * r_i
        agg_sig += sig_point.0 * rand;
        // Π(e(P_{i,j}, M'_{i,j})) where M'_{i,j} = M_{i,j} * r_i
        rhs += pairing(&G1Affine::from(agg_pk), &G2Affine::from(h * rand));
    }

    // Final pairing check: e(g1, S*) = Π(e(P_{i,j}, M'_{i,j}))
    let lhs = pairing(&G1Affine::generator(), &G2Affine::from(agg_sig));
    lhs == rhs
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(G1Projective);

impl TPublicKey for PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        G1Affine::from(self.0).to_compressed()
    }

    fn serialize_uncompressed(&self) -> [u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN] {
        G1Affine::from(self.0).to_uncompressed()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let sliced_bytes: &[u8; PUBLIC_KEY_BYTES_LEN] =
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::InvalidByteLength {
                    got: bytes.len(),
                    expected: PUBLIC_KEY_BYTES_LEN,
                })?;

        let point_opt = G1Affine::from_compressed(sliced_bytes);
        if bool::from(point_opt.is_some()) {
            let point = point_opt.unwrap();

            if bool::from(point.is_identity()) {
                return Err(Error::InvalidInfinityPublicKey);
            }

            if !bool::from(point.is_torsion_free()) {
                return Err(Error::InvalidTorsionComponent);
            }

            Ok(Self(point.into()))
        } else {
            Err(Error::InvalidPublicKey)
        }
    }

    fn deserialize_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        let sliced_bytes: &[u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN] =
            bytes.as_ref().try_into().unwrap();
        let point = G1Affine::from_uncompressed(sliced_bytes).unwrap();

        if bool::from(point.is_identity()) {
            return Err(Error::InvalidInfinityPublicKey);
        }

        if !bool::from(point.is_torsion_free()) {
            return Err(Error::InvalidTorsionComponent);
        }

        Ok(Self(point.into()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AggregatePublicKey(G1Projective);

impl TAggregatePublicKey<PublicKey> for AggregatePublicKey {
    fn to_public_key(&self) -> GenericPublicKey<PublicKey> {
        GenericPublicKey::from_point(PublicKey(self.0))
    }

    fn aggregate(pubkeys: &[GenericPublicKey<PublicKey>]) -> Result<Self, Error> {
        pubkeys.iter().try_fold(
            AggregatePublicKey(G1Projective::identity()),
            |acc, pubkey| Ok(AggregatePublicKey(acc.0.add(&pubkey.point().0))),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature(G2Projective);

impl TSignature<PublicKey> for Signature {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        G2Affine::from(self.0).to_compressed()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let sliced_bytes: &[u8; SIGNATURE_BYTES_LEN] =
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::InvalidByteLength {
                    got: bytes.len(),
                    expected: SIGNATURE_BYTES_LEN,
                })?;
        let point_opt = G2Affine::from_compressed(sliced_bytes);
        if bool::from(point_opt.is_some()) {
            let point = point_opt.unwrap();

            Ok(Self(point.into()))
        } else {
            Err(Error::InvalidSignature)
        }
    }

    fn verify(&self, pubkey: &PublicKey, msg: Hash256) -> bool {
        let h =
            <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(&[msg], DST);

        let gt1 = pairing(&G1Affine::from(pubkey.0), &G2Affine::from(h));
        let gt2 = pairing(&G1Affine::generator(), &G2Affine::from(self.0));

        gt1 == gt2
    }
}

impl std::hash::Hash for Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.serialize().hash(state)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AggregateSignature(G2Projective);

impl TAggregateSignature<PublicKey, AggregatePublicKey, Signature> for AggregateSignature {
    fn infinity() -> Self {
        Self(G2Projective::identity())
    }

    fn add_assign(&mut self, other: &Signature) {
        self.0 = self.0.add(&other.0)
    }

    fn add_assign_aggregate(&mut self, other: &Self) {
        self.0 = self.0.add(&other.0)
    }

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        G2Affine::from(self.0).to_compressed()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let sliced_bytes: &[u8; SIGNATURE_BYTES_LEN] =
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::InvalidByteLength {
                    got: bytes.len(),
                    expected: SIGNATURE_BYTES_LEN,
                })?;
        let point_opt = G2Affine::from_compressed(sliced_bytes);
        if bool::from(point_opt.is_some()) {
            let point = point_opt.unwrap();

            Ok(Self(point.into()))
        } else {
            Err(Error::InvalidSignature)
        }
    }

    fn fast_aggregate_verify(
        &self,
        msg: Hash256,
        pubkeys: &[&GenericPublicKey<PublicKey>],
    ) -> bool {
        let agg_pks_point = pubkeys
            .iter()
            .fold(
                AggregatePublicKey(G1Projective::identity()),
                |acc, pubkey| AggregatePublicKey(acc.0.add(&pubkey.point().0)),
            )
            .0;
        let h =
            <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(&[msg], DST);

        let gt1 = pairing(&G1Affine::from(agg_pks_point), &G2Affine::from(h));
        let gt2 = pairing(&G1Affine::generator(), &G2Affine::from(self.0));

        gt1 == gt2
    }

    fn aggregate_verify(&self, msgs: &[Hash256], pubkeys: &[&GenericPublicKey<PublicKey>]) -> bool {
        if msgs.len() != pubkeys.len() || msgs.is_empty() {
            return false;
        }

        let gt1 =
            msgs.iter()
                .zip(pubkeys.iter())
                .fold(Gt::identity(), |acc, (msg, pubkey)| {
                    acc + (&pairing(
                        &G1Affine::from(pubkey.point().0),
                        &G2Affine::from(<G2Projective as HashToCurve<
                            ExpandMsgXmd<sha2::Sha256>,
                        >>::hash_to_curve(&[*msg], DST)),
                    ))
                });

        let gt2 = pairing(&G1Affine::generator(), &G2Affine::from(self.0));

        gt1 == gt2
    }
}

#[derive(Clone)]
pub struct SecretKey(Scalar);

impl TSecretKey<Signature, PublicKey> for SecretKey {
    fn random() -> Self {
        let mut rng = thread_rng();
        let mut buf = [0; 64];
        rng.fill_bytes(&mut buf);
        Self(Scalar::from_bytes_wide(&buf))
    }

    fn public_key(&self) -> PublicKey {
        let point = self.0 * G1Projective::generator();
        PublicKey(point)
    }

    fn sign(&self, msg: Hash256) -> Signature {
        let h =
            <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(&[msg], DST);
        let point = h * self.0;
        Signature(point)
    }

    fn serialize(&self) -> ZeroizeHash {
        self.0.to_bytes().into()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let sliced_bytes: &[u8; SECRET_KEY_BYTES_LEN] =
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::InvalidByteLength {
                    got: bytes.len(),
                    expected: SECRET_KEY_BYTES_LEN,
                })?;
        let mut le_bytes = *sliced_bytes;
        le_bytes.reverse(); // Scalar::from_bytes_wide expects little-endian
        let scalar = Scalar::from_bytes(&le_bytes).unwrap();
        Ok(Self(scalar))
    }
}
