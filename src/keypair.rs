use crate::ed25519;
pub use crate::ed25519::Signature;
use crate::x25519;

pub enum SecretKey {
    Ed25519(ed25519::Keypair),
    X25519(x25519::StaticSecret),
}

impl From<ed25519::Keypair> for SecretKey {
    fn from(pk: ed25519::Keypair) -> Self {
        Self::Ed25519(pk)
    }
}

impl From<x25519::StaticSecret> for SecretKey {
    fn from(pk: x25519::StaticSecret) -> Self {
        Self::X25519(pk)
    }
}

impl SecretKey {
    fn ed25519(&self) -> &ed25519::Keypair {
        match self {
            SecretKey::Ed25519(pair) => pair,
            _ => panic!(),
        }
    }

    fn x25519(&self) -> &x25519::StaticSecret {
        match self {
            SecretKey::X25519(secret) => secret,
            _ => panic!(),
        }
    }
}

#[derive(Clone)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey),
    X25519(x25519::PublicKey),
}

impl From<ed25519::PublicKey> for PublicKey {
    fn from(pk: ed25519::PublicKey) -> Self {
        Self::Ed25519(pk)
    }
}

impl From<x25519::PublicKey> for PublicKey {
    fn from(pk: x25519::PublicKey) -> Self {
        Self::X25519(pk)
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(public) => public.as_bytes(),
            PublicKey::X25519(public) => public.as_bytes(),
        }
    }

    pub fn ed25519(&self) -> &ed25519::PublicKey {
        match self {
            PublicKey::Ed25519(public) => public,
            _ => panic!(),
        }
    }

    pub fn x25519(&self) -> &x25519::PublicKey {
        match self {
            PublicKey::X25519(public) => public,
            _ => panic!(),
        }
    }

    pub fn ephemeral(public: [u8; 32]) -> Self {
        x25519::PublicKey::from(public).into()
    }

    pub fn static_key(public: [u8; 32], is_sig: bool) -> Result<Self, ed25519::SignatureError> {
        if is_sig {
            Ok(ed25519::PublicKey::from_bytes(&public[..])?.into())
        } else {
            Ok(x25519::PublicKey::from(public).into())
        }
    }

    pub fn verify(&self, bytes: &[u8], sig: &Signature) -> Result<(), ed25519::SignatureError> {
        self.ed25519().verify(bytes, sig)
    }
}

pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KeyPair {
    pub fn new<T: Into<SecretKey>>(secret: T) -> Self {
        let secret = secret.into();
        let public = match &secret {
            SecretKey::Ed25519(pair) => pair.public.into(),
            SecretKey::X25519(secret) => x25519::PublicKey::from(secret).into(),
        };
        Self { secret, public }
    }

    pub fn ephemeral() -> Self {
        let secret = x25519::StaticSecret::new(&mut rand::rngs::OsRng);
        Self::new(secret)
    }

    pub fn dh(&self, public: &PublicKey) -> x25519::SharedSecret {
        self.secret.x25519().clone().diffie_hellman(public.x25519())
    }

    pub fn sign(&self, bytes: &[u8]) -> ed25519::Signature {
        self.secret.ed25519().sign(bytes)
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}
