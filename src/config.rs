use crate::patterns::HandshakePattern;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

// The following constants represent the details of this implementation of the
// Noise specification.
pub const DISCO_DRAFT_VERSION: &[u8] = b"3";
pub const NOISE_DH: &[u8] = b"25519";

// The following constants are taken directly from the Noise specification.
pub const NOISE_MAX_MSG_SIZE: usize = 65535;
pub const NOISE_TAG_SIZE: usize = 16;
pub const NOISE_MAX_PLAINTEXT_SIZE: usize = NOISE_MAX_MSG_SIZE - NOISE_TAG_SIZE;

// Should match SharedSecret and StaticSecret defined in x25519.
pub const DH_SIZE: usize = 32;
pub const KEY_SIZE: usize = 32;

/// Role in the handshake process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Initiates the handshake.
    Initiator,
    /// Responds to the handshake.
    Responder,
}

/// Public key verifier.
pub trait PublicKeyVerifier {
    /// Verify a public key given a proof.
    fn verify(&self, pub_key: &PublicKey, proof: &[u8]) -> bool;
}

pub struct Config {
    pub(crate) handshake_pattern: HandshakePattern,
    pub(crate) role: Role,
    pub(crate) secret: StaticSecret,
    pub(crate) remote_public: Option<PublicKey>,
    pub(crate) prologue: Box<[u8]>,
    pub(crate) public_key_proof: Option<Box<[u8]>>,
    pub(crate) public_key_verifier: Option<Box<dyn PublicKeyVerifier>>,
    pub(crate) preshared_secret: Option<SharedSecret>,
    pub(crate) half_duplex: bool,
}

/// Config builder.
pub struct ConfigBuilder {
    handshake_pattern: HandshakePattern,
    role: Role,
    secret: Option<StaticSecret>,
    remote_public: Option<PublicKey>,
    prologue: Option<Box<[u8]>>,
    public_key_proof: Option<Box<[u8]>>,
    public_key_verifier: Option<Box<dyn PublicKeyVerifier>>,
    preshared_secret: Option<SharedSecret>,
    half_duplex: bool,
}

impl ConfigBuilder {
    /// Creates a new config builder for a given handshake pattern and role.
    pub fn new(handshake_pattern: HandshakePattern, role: Role) -> Self {
        Self {
            handshake_pattern,
            role,
            secret: None,
            remote_public: None,
            prologue: None,
            public_key_proof: None,
            public_key_verifier: None,
            preshared_secret: None,
            half_duplex: false,
        }
    }

    /// Static secret for the peer.
    pub fn secret(mut self, secret: StaticSecret) -> Self {
        self.secret = Some(secret);
        self
    }

    /// The remote peer's static public key.
    pub fn remote_public(mut self, public: PublicKey) -> Self {
        self.remote_public = Some(public);
        self
    }

    /// Any unencrypted messages that the client and the server exchanged in
    /// this session prior to the handshake.
    pub fn prologue(mut self, prologue: Vec<u8>) -> Self {
        self.prologue = Some(prologue.into_boxed_slice());
        self
    }

    /// If the chosen handshake pattern requires the current peer to send a
    /// static public key as part of the handshake, this proof over the key is
    /// mandatory in order for the other peer to verify the current peer's key.
    pub fn public_key_proof(mut self, proof: Vec<u8>) -> Self {
        self.public_key_proof = Some(proof.into_boxed_slice());
        self
    }

    /// If the chosen handshake pattern requires the remote peer to send an
    /// unknown static public key as part of the handshake, this callback is
    /// mandatory in order to validate it.
    pub fn public_key_verifier<TVerifier>(mut self, verifier: TVerifier) -> Self
    where
        TVerifier: PublicKeyVerifier + 'static,
    {
        self.public_key_verifier = Some(Box::new(verifier));
        self
    }

    /// A pre-shared key for handshake patterns including a `psk` token.
    pub fn preshared_secret(mut self, secret: SharedSecret) -> Self {
        self.preshared_secret = Some(secret);
        self
    }

    /// By default a noise protocol is full-duplex, meaning that both the
    /// client and the server can write on the channel at the same time.
    /// Setting this value to true will require the peers to write and read in
    /// turns. If this requirement is not respected by the application, the
    /// consequences could be catastrophic.
    pub fn half_duplex(mut self) -> Self {
        self.half_duplex = true;
        self
    }

    /// Build a disco config.
    pub fn build(self) -> Config {
        match self.handshake_pattern.name {
            b"NX" | b"KX" | b"XX" | b"IX" => match self.role {
                Role::Initiator => assert!(self.public_key_verifier.is_some()),
                Role::Responder => assert!(self.public_key_proof.is_some()),
            },
            _ => {}
        }

        match self.handshake_pattern.name {
            b"XN" | b"XK" | b"XX" | b"X" | b"IN" | b"IK" | b"IX" => match self.role {
                Role::Initiator => assert!(self.public_key_proof.is_some()),
                Role::Responder => assert!(self.public_key_verifier.is_some()),
            },
            _ => {}
        }

        match self.handshake_pattern.name {
            b"K" | b"KN" | b"KK" | b"KX" => match self.role {
                Role::Initiator => assert!(self.remote_public.is_some()),
                _ => {}
            },
            _ => {}
        }

        match self.handshake_pattern.name {
            b"NK" | b"KK" | b"XK" | b"IK" => match self.role {
                Role::Initiator => {}
                Role::Responder => assert!(self.remote_public.is_some()),
            },
            _ => {}
        }

        match self.handshake_pattern.name {
            b"NNPsk2" => assert!(self.preshared_secret.is_some()),
            _ => {}
        }

        Config {
            handshake_pattern: self.handshake_pattern,
            role: self.role,
            secret: self.secret.expect("secret key was not provided"),
            remote_public: self.remote_public,
            prologue: self.prologue.unwrap_or(vec![].into_boxed_slice()),
            public_key_proof: self.public_key_proof,
            public_key_verifier: self.public_key_verifier,
            preshared_secret: self.preshared_secret,
            half_duplex: self.half_duplex,
        }
    }
}
