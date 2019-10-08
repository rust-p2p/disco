//! Implementation of the HandshakeState.
use crate::constants::{DH_LEN, KEY_LEN, MAX_MSG_LEN, TAG_LEN};
use crate::patterns::{HandshakePattern, MessagePattern, PreMessagePatternPair, Token};
use crate::symmetric_state::SymmetricState;
use crate::x25519::{PublicKey, SharedSecret, StaticSecret};
use core::ops::Deref;
use failure::Fail;
use std::collections::VecDeque;
use strobe_rs::{Strobe, STROBE_VERSION};

/// Read error returned by `read_message`.
#[derive(Debug, Fail)]
pub enum ReadError {
    /// Message is invalid.
    #[fail(display = "Invalid message")]
    InvalidMessage,
    /// Message authentication failed.
    #[fail(display = "Invalid mac")]
    AuthError,
}

impl From<strobe_rs::AuthError> for ReadError {
    fn from(_: strobe_rs::AuthError) -> Self {
        Self::AuthError
    }
}

/// Role in the handshake process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Initiates the handshake.
    Initiator,
    /// Responds to the handshake.
    Responder,
}

/// The state of the handshake process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Turn {
    Read,
    Write,
}

struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    fn new(secret: StaticSecret) -> Self {
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    fn generate() -> Self {
        let secret = StaticSecret::new(&mut rand::rngs::OsRng);
        Self::new(secret)
    }

    fn dh(&self, public: &PublicKey) -> SharedSecret {
        self.secret.clone().diffie_hellman(public)
    }

    fn public(&self) -> &PublicKey {
        &self.public
    }
}

struct PanicOption<T>(Option<T>);

impl<T> Deref for PanicOption<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

/// An object that encodes handshake state. This is the primary API for
/// initiating Disco sessions.
pub struct HandshakeState {
    /// The SymmetricState object.
    symmetric_state: SymmetricState,
    /// The local static key pair.
    s: PanicOption<KeyPair>,
    /// The local ephemeral key pair.
    e: PanicOption<KeyPair>,
    /// The remote party's static public key.
    rs: PanicOption<PublicKey>,
    /// The remote party's ephemeral public key.
    re: PanicOption<PublicKey>,
    /// Indicates the role (Initiator or Responder).
    role: Role,
    /// A sequence of message patterns. Each message pattern is a sequence of
    /// tokens from the set (e, s, ee, es, se, ss, psk).
    message_patterns: VecDeque<MessagePattern>,
    /// Turn in the handshake process (Read or Write).
    turn: Turn,
    /// Pre-shared key.
    psk: Option<[u8; KEY_LEN]>,
}

impl HandshakeState {
    /// Initializes the HandshakeState.
    pub fn new(
        handshake_pattern: HandshakePattern,
        role: Role,
        prologue: &[u8],
        s: Option<StaticSecret>,
        e: Option<StaticSecret>,
        rs: Option<PublicKey>,
        re: Option<PublicKey>,
        psk: Option<[u8; KEY_LEN]>,
    ) -> HandshakeState {
        let protocol_name = format!(
            "Noise_{}_25519_STROBEv{}",
            handshake_pattern.name, STROBE_VERSION
        );
        let mut symmetric_state = SymmetricState::new(protocol_name.as_bytes());
        symmetric_state.mix_hash(prologue);

        let message_patterns = VecDeque::from(handshake_pattern.message_patterns.to_vec());
        let turn = match role {
            Role::Initiator => Turn::Write,
            Role::Responder => Turn::Read,
        };

        let s = PanicOption(s.map(KeyPair::new));
        let e = PanicOption(e.map(KeyPair::new));
        let rs = PanicOption(rs);
        let re = PanicOption(re);

        let mut h = HandshakeState {
            symmetric_state,
            s,
            e,
            rs,
            re,
            role,
            message_patterns,
            turn,
            psk,
        };

        h.initialize(&handshake_pattern.pre_message_patterns);
        h
    }

    /// Calls mix_hash() once for each public key listed in the pre-messages
    /// from handshake_pattern, with the specified public key as input (see
    /// Section 7 for an explanation of pre-messages).
    /// If both initiator and responder have pre-messages, the initiator's
    /// public keys are hashed first.
    fn initialize(&mut self, pre_message_patterns: &PreMessagePatternPair) {
        // Initiator pre-message pattern
        for token in pre_message_patterns.initiator {
            if let Token::S = token {
                match self.role {
                    Role::Initiator => {
                        let s = self.s.public().clone();
                        self.symmetric_state.mix_hash(s.as_bytes());
                    }
                    Role::Responder => {
                        let rs = self.rs.clone();
                        self.symmetric_state.mix_hash(rs.as_bytes());
                    }
                }
            } else {
                panic!("disco: Pre-message token not supported: {:?}", token)
            }
        }

        // Responder pre-message pattern
        for token in pre_message_patterns.responder {
            if let Token::S = token {
                match self.role {
                    Role::Initiator => {
                        let rs = self.rs.clone();
                        self.symmetric_state.mix_hash(rs.as_bytes());
                    }
                    Role::Responder => {
                        let s = self.s.public().clone();
                        self.symmetric_state.mix_hash(s.as_bytes());
                    }
                }
            } else {
                panic!("disco: Pre-message token not supported: {:?}", token)
            }
        }
    }

    /// Returns if the handshake is complete.
    pub fn is_handshake_complete(&self) -> bool {
        self.message_patterns.len() == 0
    }

    /// Takes a payload byte sequence with may be zero-length, and returns a
    /// message buffer.
    pub fn write_message(&mut self, payload: &[u8]) -> Vec<u8> {
        assert!(self.turn == Turn::Write);
        assert!(payload.len() <= MAX_MSG_LEN - TAG_LEN * 2 - DH_LEN * 2);

        let pattern = self
            .message_patterns
            .pop_front()
            .expect("No more patterns left to process");
        let mut message = Vec::with_capacity(MAX_MSG_LEN);

        for token in pattern {
            match token {
                Token::E => {
                    let e = KeyPair::generate();
                    message.extend_from_slice(e.public().as_bytes());
                    self.symmetric_state.mix_hash(e.public().as_bytes());
                    if self.psk.is_some() {
                        self.symmetric_state.mix_key(e.public().as_bytes());
                    }
                    self.e = PanicOption(Some(e));
                }

                Token::S => {
                    let s = self.s.public();
                    let ct = self.symmetric_state.encrypt_and_hash(s.as_bytes());
                    message.extend(ct);
                }

                Token::EE => {
                    let ee = self.e.dh(&self.re);
                    self.symmetric_state.mix_key(ee.as_bytes());
                }

                Token::ES => {
                    let es = match self.role {
                        Role::Initiator => self.e.dh(&self.rs),
                        Role::Responder => self.s.dh(&self.re),
                    };
                    self.symmetric_state.mix_key(es.as_bytes());
                }

                Token::SE => {
                    let se = match self.role {
                        Role::Initiator => self.s.dh(&self.re),
                        Role::Responder => self.e.dh(&self.rs),
                    };
                    self.symmetric_state.mix_key(se.as_bytes());
                }

                Token::SS => {
                    let ss = self.s.dh(&self.rs);
                    self.symmetric_state.mix_key(ss.as_bytes());
                }

                Token::Psk => {
                    let psk = self.psk.as_ref().unwrap();
                    self.symmetric_state.mix_key_and_hash(psk);
                }
            }
        }

        let ct = self.symmetric_state.encrypt_and_hash(&payload);
        message.extend(ct);

        // Next time it's our turn to read
        self.turn = Turn::Read;

        message
    }

    /// Takes a byte sequence containing a Noise handshake message and returns
    /// the decrypted payload.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, ReadError> {
        assert!(self.turn == Turn::Read);
        assert!(message.len() <= MAX_MSG_LEN);

        let pattern = self
            .message_patterns
            .pop_front()
            .expect("No more patterns left to process");
        let mut i = 0;

        for token in pattern {
            match token {
                Token::E => {
                    let i2 = i + DH_LEN;
                    if i2 >= message.len() {
                        return Err(ReadError::InvalidMessage);
                    }
                    let mut e = [0u8; DH_LEN];
                    e.copy_from_slice(&message[i..i2]);
                    self.symmetric_state.mix_hash(&e);
                    if self.psk.is_some() {
                        self.symmetric_state.mix_key(&e);
                    }
                    self.re = PanicOption(Some(PublicKey::from(e)));
                    i = i2;
                }

                Token::S => {
                    let tag_size = if self.symmetric_state.has_key() {
                        TAG_LEN
                    } else {
                        0
                    };
                    let i2 = i + DH_LEN + tag_size;
                    if i2 >= message.len() {
                        return Err(ReadError::InvalidMessage);
                    }
                    let pt = self.symmetric_state.decrypt_and_hash(&message[i..i2])?;
                    let mut rs = [0u8; DH_LEN];
                    rs.copy_from_slice(&pt);
                    self.rs = PanicOption(Some(PublicKey::from(rs)));
                    i = i2;
                }

                Token::EE => {
                    let ee = self.e.dh(&self.re);
                    self.symmetric_state.mix_key(ee.as_bytes());
                }

                Token::ES => {
                    let es = match self.role {
                        Role::Initiator => self.e.dh(&self.rs),
                        Role::Responder => self.s.dh(&self.re),
                    };
                    self.symmetric_state.mix_key(es.as_bytes());
                }

                Token::SE => {
                    let se = match self.role {
                        Role::Initiator => self.s.dh(&self.re),
                        Role::Responder => self.e.dh(&self.rs),
                    };
                    self.symmetric_state.mix_key(se.as_bytes());
                }

                Token::SS => {
                    let ss = self.s.dh(&self.rs);
                    self.symmetric_state.mix_key(ss.as_bytes());
                }

                Token::Psk => {
                    let psk = self.psk.as_ref().unwrap();
                    self.symmetric_state.mix_key_and_hash(psk);
                }
            }
        }

        let pt = self.symmetric_state.decrypt_and_hash(&message[i..])?;

        // Next time it's our turn to write
        self.turn = Turn::Write;

        Ok(pt)
    }

    /// Returns a pair of Strobe objects for encrypting transport messages.
    pub fn finalize(self) -> (Strobe, Strobe) {
        assert!(self.is_handshake_complete());
        self.symmetric_state.split()
    }
}
