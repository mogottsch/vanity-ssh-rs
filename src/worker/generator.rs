use crate::core::keypair::{KeyPair, generate_keypair_batch, BATCH_SIZE};
use crate::core::pattern::{Pattern, public_key_matches_pattern};

pub fn generate_and_check_batch(patterns: &[Pattern]) -> Option<(KeyPair, Pattern)> {
    let keypairs = generate_keypair_batch(BATCH_SIZE);
    
    for keypair in keypairs {
        if let Some(pattern) = patterns
            .iter()
            .find(|p| public_key_matches_pattern(&keypair, p))
        {
            return Some((keypair, pattern.clone()));
        }
    }
    
    None
}
