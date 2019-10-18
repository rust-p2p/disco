//! Implementation of the HandshakeState.
use crate::constants::{DH_LEN, KEY_LEN, MAX_MSG_LEN, SIG_LEN, TAG_LEN};
use crate::keypair::{KeyPair, PublicKey, SecretKey, Signature};
use crate::patterns::{Handshake, Role, Token};
use crate::stateless_transport_state::StatelessTransportState;
use crate::symmetric_state::SymmetricState;
use crate::transport_state::TransportState;
use core::ops::{Deref, DerefMut};
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
    /// Invalid signature.
    #[fail(display = "Invalid signature")]
    SignatureError,
}

impl From<strobe_rs::AuthError> for ReadError {
    fn from(_: strobe_rs::AuthError) -> Self {
        Self::AuthError
    }
}

impl From<crate::ed25519::SignatureError> for ReadError {
    fn from(_: crate::ed25519::SignatureError) -> Self {
        Self::SignatureError
    }
}

/// The state of the handshake process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Turn {
    Read,
    Write,
}

pub struct PanicOption<T>(Option<T>);

impl<T> PanicOption<T> {
    fn get(&self) -> Option<&T> {
        self.0.as_ref()
    }
}

impl<T> Deref for PanicOption<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get().unwrap()
    }
}

impl<T> DerefMut for PanicOption<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().unwrap()
    }
}

/// An object that encodes handshake state. This is the primary API for
/// initiating Disco sessions.
pub struct HandshakeState<'a> {
    /// The SymmetricState object.
    symmetric_state: SymmetricState,
    /// The local static key pair.
    s: PanicOption<KeyPair<'a>>,
    /// The local ephemeral key pair.
    e: PanicOption<KeyPair<'a>>,
    /// The remote party's static public key.
    rs: PanicOption<PublicKey>,
    /// The remote party's ephemeral public key.
    re: PanicOption<PublicKey>,
    /// Indicates the role (Initiator or Responder).
    role: Role,
    /// A sequence of message patterns. Each message pattern is a sequence of
    /// tokens from the set (e, s, ee, es, se, ss, psk).
    message_patterns: VecDeque<Vec<Token>>,
    /// Turn in the handshake process (Read or Write).
    turn: Turn,
    /// Pre-shared key.
    psks: Vec<[u8; KEY_LEN]>,
    /// Is a oneway pattern.
    oneway: bool,
    /// Is a signature pattern.
    sig: bool,
    #[allow(unused)]
    /// Is a fallback pattern.
    fallback: bool,
}

impl<'a> HandshakeState<'a> {
    /// Initializes the HandshakeState.
    pub(crate) fn new(
        handshake: Handshake,
        role: Role,
        prologue: &[u8],
        s: Option<SecretKey<'a>>,
        e: Option<SecretKey<'a>>,
        rs: Option<PublicKey>,
        re: Option<PublicKey>,
        psks: Vec<[u8; KEY_LEN]>,
    ) -> HandshakeState<'a> {
        let protocol_name = format!("Noise_{}_25519_STROBEv{}", handshake.name(), STROBE_VERSION);
        let mut symmetric_state = SymmetricState::new(protocol_name.as_bytes());
        symmetric_state.mix_hash(prologue);

        let (initiator, responder, message_pattern) = handshake.tokens();
        let message_patterns = VecDeque::from(message_pattern);
        let oneway = handshake.pattern().is_oneway();
        let sig = handshake.is_sig();
        let fallback = handshake.is_fallback();
        let turn = match role {
            Role::Initiator => Turn::Write,
            Role::Responder => Turn::Read,
        };

        let s = PanicOption(s.map(KeyPair::new));
        let e = PanicOption(e.map(KeyPair::new));
        let rs = PanicOption(rs);
        let re = PanicOption(re);
        let psks = psks.into_iter().rev().collect();

        let mut h = HandshakeState {
            symmetric_state,
            s,
            e,
            rs,
            re,
            role,
            message_patterns,
            turn,
            psks,
            oneway,
            sig,
            fallback,
        };

        h.initialize(initiator, responder);
        h
    }

    /// Calls mix_hash() once for each public key listed in the pre-messages
    /// from handshake_pattern, with the specified public key as input (see
    /// Section 7 for an explanation of pre-messages).
    /// If both initiator and responder have pre-messages, the initiator's
    /// public keys are hashed first.
    fn initialize(&mut self, initiator: &[Token], responder: &[Token]) {
        // Initiator pre-message pattern
        for token in initiator {
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
        for token in responder {
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
                    let e = KeyPair::ephemeral();
                    message.extend_from_slice(e.public().as_bytes());
                    self.symmetric_state.mix_hash(e.public().as_bytes());
                    if self.psks.len() > 0 {
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
                    let psk = self.psks.pop().unwrap();
                    self.symmetric_state.mix_key_and_hash(&psk[..]);
                }

                Token::Sig => {
                    let hash = self.get_handshake_hash();
                    let sig = self.s.sign(&hash);
                    let ct = self.symmetric_state.encrypt_and_hash(&sig.to_bytes()[..]);
                    message.extend(ct);
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
                    if i2 > message.len() {
                        return Err(ReadError::InvalidMessage);
                    }
                    let mut e = [0u8; DH_LEN];
                    e.copy_from_slice(&message[i..i2]);
                    self.symmetric_state.mix_hash(&e);
                    if self.psks.len() > 0 {
                        self.symmetric_state.mix_key(&e);
                    }
                    self.re = PanicOption(Some(PublicKey::ephemeral(e)));
                    i = i2;
                }

                Token::S => {
                    let tag_size = if self.symmetric_state.has_key() {
                        TAG_LEN
                    } else {
                        0
                    };
                    let i2 = i + DH_LEN + tag_size;
                    if i2 > message.len() {
                        return Err(ReadError::InvalidMessage);
                    }
                    let pt = self.symmetric_state.decrypt_and_hash(&message[i..i2])?;
                    let mut rs = [0u8; DH_LEN];
                    rs.copy_from_slice(&pt);
                    let rs = PublicKey::static_key(rs, self.sig)?;
                    self.rs = PanicOption(Some(rs));
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
                    let psk = self.psks.pop().unwrap();
                    self.symmetric_state.mix_key_and_hash(&psk[..]);
                }

                Token::Sig => {
                    let tag_size = if self.symmetric_state.has_key() {
                        TAG_LEN
                    } else {
                        0
                    };
                    let i2 = i + SIG_LEN + tag_size;
                    if i2 > message.len() {
                        return Err(ReadError::InvalidMessage);
                    }
                    let hash = self.get_handshake_hash();
                    let pt = self.symmetric_state.decrypt_and_hash(&message[i..i2])?;
                    let mut sig = [0u8; SIG_LEN];
                    sig.copy_from_slice(&pt);
                    let sig = Signature::from_bytes(&sig[..])?;
                    self.rs.verify(&hash, &sig)?;
                    i = i2;
                }
            }
        }

        let pt = self.symmetric_state.decrypt_and_hash(&message[i..])?;

        // Next time it's our turn to write
        self.turn = Turn::Write;

        Ok(pt)
    }

    /// Get the remote party's static public key, if available.
    ///
    /// Note: will return `None` if either the cosen Noise pattern
    /// doesn't necessitate a remote static key, *or* if the remote
    /// static key is not yet known.
    pub fn get_remote_static(&self) -> Option<&PublicKey> {
        self.rs.get()
    }

    /// Get the handshake hash.
    ///
    /// Returns the state of the session useful for channel binding.
    ///
    /// 11.2. Channel binding
    ///
    /// Parties may wish to execute a Noise protocol, then perform
    /// authentication at the application layer using signatures, passwords, or
    /// something else.
    ///
    /// To support this, Noise libraries may call `get_handshake_hash` after
    /// the handshake is complete and expose the returned value to the
    /// application as a handshake hash which uniquely identifies the Noise
    /// session.
    ///
    /// Parties can then sign the handshake hash, or hash it along with their
    /// password, to get an authentication token which has a "channel binding"
    /// property: the token can't be used by the receiving party with a
    /// different session.
    pub fn get_handshake_hash(&mut self) -> Vec<u8> {
        self.symmetric_state.get_handshake_hash()
    }

    /// Checks if the handshake is finished.
    pub fn is_handshake_finished(&self) -> bool {
        self.message_patterns.len() == 0
    }

    fn split(self, ratchet: bool) -> (PanicOption<Strobe>, PanicOption<Strobe>) {
        assert!(self.is_handshake_finished());
        let (mut init, mut resp) = self.symmetric_state.split();
        if ratchet {
            init.meta_ratchet(0, false);
            resp.meta_ratchet(0, false);
        }
        let init = PanicOption(Some(init));
        let resp = if self.oneway {
            PanicOption(None)
        } else {
            PanicOption(Some(resp))
        };
        match self.role {
            Role::Initiator => (init, resp),
            Role::Responder => (resp, init),
        }
    }

    /// Returns a transport state object for encrypting transport messages.
    pub fn into_transport_mode(self) -> TransportState {
        let (tx, rx) = self.split(false);
        TransportState { tx, rx }
    }

    /// Returns a stateless transport state object for encrypting transport
    /// messages.
    pub fn into_stateless_transport_mode(self) -> StatelessTransportState {
        let (tx, rx) = self.split(true);
        StatelessTransportState { tx, rx }
    }
}
