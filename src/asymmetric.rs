use rand::{thread_rng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// A constant specifying the size in bytes of public keys and DH outputs. For security reasons,
/// DH_SIZE must be 32 or greater.
pub const DH_SIZE: usize = 32;

/// Contains a private and a public part. It can be generated via the `gen` or `from_priv_key`
/// functions. The public part can also be extracted via the `pub_key_bytes` function.
pub struct KeyPair {
    pub(crate) pub_key: PublicKey,
    priv_key: StaticSecret,
}

impl KeyPair {
    /// Creates creates a X25519 static keypair out of a private key.
    pub fn from_priv_key(priv_key: [u8; 32]) -> KeyPair {
        let priv_key = StaticSecret::from(priv_key);
        let pub_key = PublicKey::from(&priv_key);
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
    pub fn pub_key_bytes(&self) -> &[u8; DH_SIZE] {
        self.pub_key.as_bytes()
    }
}

/// Performs a Diffie-Hellman exchange with the given private key and public key. Returns the byte
/// representation of the resulting point.
pub fn dh(key_pair: &KeyPair, pub_key: &[u8; DH_SIZE]) -> [u8; DH_SIZE] {
    let pub_key = PublicKey::from(pub_key.clone());
    key_pair
        .priv_key
        .diffie_hellman(&pub_key)
        .as_bytes()
        .to_owned()
}
