use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use ed25519_dalek::SecretKey;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use rand::RngCore;
use rand::rngs::OsRng;

pub const BATCH_SIZE: usize = 100;

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: CompressedEdwardsY,
}

pub fn generate_keypair_batch(batch_size: usize) -> Vec<KeyPair> {
    let mut csprng = OsRng;
    let mut secret_keys = Vec::with_capacity(batch_size);
    let mut public_points = Vec::with_capacity(batch_size);

    for _ in 0..batch_size {
        let mut secret_key = SecretKey::default();
        csprng.fill_bytes(&mut secret_key);
        let expanded_secret_key = ExpandedSecretKey::from(&secret_key);
        let public_point = EdwardsPoint::mul_base(&expanded_secret_key.scalar);
        secret_keys.push(secret_key);
        public_points.push(public_point);
    }

    let compressed_points = EdwardsPoint::compress_batch(&public_points);

    secret_keys
        .into_iter()
        .zip(compressed_points.into_iter())
        .map(|(secret_key, compressed)| KeyPair {
            secret_key,
            public_key: compressed,
        })
        .collect()
}

pub mod bench_helpers {
    use super::*;

    #[allow(dead_code)]
    pub fn generate_secret_key() -> SecretKey {
        let mut csprng = OsRng;
        let mut secret_key = SecretKey::default();
        csprng.fill_bytes(&mut secret_key);
        secret_key
    }

    #[allow(dead_code)]
    pub fn expand_secret_key(secret_key: &SecretKey) -> ExpandedSecretKey {
        ExpandedSecretKey::from(secret_key)
    }

    #[allow(dead_code)]
    pub fn compute_mul_base(expanded: &ExpandedSecretKey) -> EdwardsPoint {
        EdwardsPoint::mul_base(&expanded.scalar)
    }

    #[allow(dead_code)]
    pub fn compress_point(point: &EdwardsPoint) -> CompressedEdwardsY {
        point.compress()
    }
}
