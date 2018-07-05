use curve25519_dalek::montgomery::MontgomeryPoint;
use rand::{thread_rng, RngCore};
use x25519_dalek;

/// A constant specifying the size in bytes of public keys and DH outputs. For security reasons,
/// DH_LEN must be 32 or greater.
pub const DH_LEN: usize = 32;

/// Contains a private and a public part. It can be generated via the `gen` or `from_priv_key`
/// functions. The public part can also be extracted via the `pub_key_bytes` function.
pub struct KeyPair {
    pub_key: MontgomeryPoint,
    priv_key: [u8; 32],
}

impl KeyPair {
    /// Creates creates a X25519 static keypair out of a private key.
    pub fn from_priv_key(priv_key: [u8; 32]) -> KeyPair {
        let pub_key = x25519_dalek::generate_public(&priv_key);
        KeyPair { pub_key, priv_key }
    }

    /// Creates a secure random X25519 static keypair.
    pub fn gen() -> KeyPair {
        let mut rng = thread_rng();
        let mut priv_key = [0u8; 32];
        rng.fill_bytes(&mut priv_key);
        KeyPair::from_priv_key(priv_key)
    }

    /// Dumps the bytes of this keypair's public key.
    pub fn pub_key_bytes(&self) -> &[u8; DH_LEN] {
        self.pub_key.as_bytes()
    }
}

/// Performs a Diffie-Hellman exchange with the given private key and public key. Returns the byte
/// representation of the resulting point.
pub fn dh(key_pair: &KeyPair, pub_key: &[u8; DH_LEN]) -> [u8; DH_LEN] {
    x25519_dalek::diffie_hellman(&key_pair.priv_key, pub_key)
}
