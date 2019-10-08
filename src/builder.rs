use crate::constants::KEY_LEN;
use crate::handshake_state::{HandshakeState, Role};
use crate::patterns::HandshakePattern;
use x25519_dalek::{PublicKey, StaticSecret};

/// Session builder.
pub struct SessionBuilder {
    handshake_pattern: HandshakePattern,
    secret: Option<StaticSecret>,
    remote_public: Option<PublicKey>,
    prologue: Option<Vec<u8>>,
    preshared_secret: Option<[u8; KEY_LEN]>,
}

impl SessionBuilder {
    /// Creates a new config builder for a given handshake pattern and role.
    pub fn new(handshake_pattern: HandshakePattern) -> Self {
        Self {
            handshake_pattern,
            secret: None,
            remote_public: None,
            prologue: None,
            preshared_secret: None,
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
        self.prologue = Some(prologue);
        self
    }

    /// A pre-shared key for handshake patterns including a `psk` token.
    pub fn preshared_secret(mut self, secret: [u8; KEY_LEN]) -> Self {
        self.preshared_secret = Some(secret);
        self
    }

    /// Build an initiator session.
    pub fn build_initiator(self) -> HandshakeState {
        self.build(Role::Initiator)
    }

    /// Build a responder session.
    pub fn build_responder(self) -> HandshakeState {
        self.build(Role::Responder)
    }

    /// Builds a session.
    fn build(mut self, role: Role) -> HandshakeState {
        match self.handshake_pattern.name {
            "K" | "KN" | "KK" | "KX" => match role {
                Role::Initiator => assert!(self.remote_public.is_some()),
                _ => {}
            },
            _ => {}
        }

        match self.handshake_pattern.name {
            "NK" | "KK" | "XK" | "IK" => match role {
                Role::Initiator => {}
                Role::Responder => assert!(self.remote_public.is_some()),
            },
            _ => {}
        }

        match self.handshake_pattern.name {
            "NNPsk2" => assert!(self.preshared_secret.is_some()),
            _ => {}
        }

        let prologue = self.prologue.take().unwrap_or_default();

        HandshakeState::new(
            self.handshake_pattern,
            role,
            &prologue,
            self.secret,
            None,
            self.remote_public,
            None,
            self.preshared_secret,
        )
    }
}
