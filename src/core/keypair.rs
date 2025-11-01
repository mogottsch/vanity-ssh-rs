use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub const BATCH_SIZE: usize = 100;

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: VerifyingKey,
    pub private_key: SigningKey,
}

pub fn generate_keypair() -> KeyPair {
    let mut csprng = OsRng;
    let private_key = SigningKey::generate(&mut csprng);
    let public_key = private_key.verifying_key();

    KeyPair {
        public_key,
        private_key,
    }
}

pub fn generate_keypair_batch(batch_size: usize) -> Vec<KeyPair> {
    let mut csprng = OsRng;
    (0..batch_size)
        .map(|_| {
            let private_key = SigningKey::generate(&mut csprng);
            let public_key = private_key.verifying_key();
            KeyPair {
                public_key,
                private_key,
            }
        })
        .collect()
}
