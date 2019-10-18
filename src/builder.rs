use crate::constants::KEY_LEN;
use crate::handshake_state::HandshakeState;
use crate::keypair::{PublicKey, SecretKey};
use crate::patterns::{Handshake, Role};

/// Session builder.
#[derive(Clone)]
pub struct SessionBuilder<'a> {
    handshake: Handshake,
    secret: Option<SecretKey<'a>>,
    remote_public: Option<PublicKey>,
    prologue: Option<Vec<u8>>,
    psks: Vec<[u8; KEY_LEN]>,
}

impl<'a> SessionBuilder<'a> {
    /// Creates a new config builder for a given handshake pattern and role.
    pub fn new(pattern: &str) -> Self {
        let handshake = pattern.parse().unwrap();
        Self {
            handshake,
            secret: None,
            remote_public: None,
            prologue: None,
            psks: vec![],
        }
    }

    /// Static secret for the peer.
    pub fn secret<T: Into<SecretKey<'a>>>(mut self, secret: T) -> Self {
        self.secret = Some(secret.into());
        self
    }

    /// The remote peer's static public key.
    pub fn remote_public<T: Into<PublicKey>>(mut self, public: T) -> Self {
        self.remote_public = Some(public.into());
        self
    }

    /// Any unencrypted messages that the client and the server exchanged in
    /// this session prior to the handshake.
    pub fn prologue(mut self, prologue: Vec<u8>) -> Self {
        self.prologue = Some(prologue);
        self
    }

    /// A pre-shared key for handshake patterns including a `psk` token.
    pub fn add_psk(mut self, secret: [u8; KEY_LEN]) -> Self {
        self.psks.push(secret);
        self
    }

    /// Build an initiator session.
    pub fn build_initiator(self) -> HandshakeState<'a> {
        self.build(Role::Initiator)
    }

    /// Build a responder session.
    pub fn build_responder(self) -> HandshakeState<'a> {
        self.build(Role::Responder)
    }

    /// Builds a session.
    fn build(mut self, role: Role) -> HandshakeState<'a> {
        if self.handshake.pattern().needs_local_static_key(role) {
            match self.secret {
                Some(SecretKey::Ed25519(_)) => assert!(self.handshake.is_sig()),
                Some(SecretKey::X25519(_)) => assert!(!self.handshake.is_sig()),
                None => panic!(),
            }
        }

        if self.handshake.pattern().needs_known_remote_pubkey(role) {
            match self.remote_public {
                Some(PublicKey::Ed25519(_)) => assert!(self.handshake.is_sig()),
                Some(PublicKey::X25519(_)) => assert!(!self.handshake.is_sig()),
                None => panic!(),
            }
        }

        assert!(self.handshake.number_of_psks() == self.psks.len());

        let prologue = self.prologue.take().unwrap_or_default();

        HandshakeState::new(
            self.handshake,
            role,
            &prologue,
            self.secret,
            None,
            self.remote_public,
            None,
            self.psks,
        )
    }
}
