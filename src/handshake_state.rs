//! Implementation of the HandshakeState.
use crate::config::{DH_SIZE, KEY_SIZE, MAX_PLAINTEXT_SIZE, TAG_SIZE};
use crate::patterns::{HandshakePattern, MessagePattern, PreMessagePatternPair, Token};
use crate::symmetric_state::SymmetricState;
use crate::x25519::{PublicKey, SharedSecret, StaticSecret};
use failure::Fail;
use std::collections::VecDeque;
use strobe_rs::{Strobe, STROBE_VERSION};

#[derive(Debug, Fail)]
pub enum DiscoWriteError {
    #[fail(display = "message to long")]
    TooLongErr,
}

#[derive(Debug, Fail)]
pub enum DiscoReadError {
    #[fail(display = "{}", _0)]
    ParseErr(&'static str),
    #[fail(display = "authentication error")]
    AuthErr,
    #[fail(display = "message to long")]
    TooLongErr,
}

// An object that encodes handshake state. This is the primary API for initiating Disco sessions.
pub struct HandshakeState {
    symm_state: SymmetricState,
    ephemeral_secret: Option<StaticSecret>,
    ephemeral_public: Option<PublicKey>,
    static_secret: Option<StaticSecret>,
    static_public: Option<PublicKey>,
    remote_ephemeral: Option<PublicKey>,
    remote_static: Option<PublicKey>,
    // Are we the initiator?
    initiator: bool,
    message_pats: VecDeque<MessagePattern>,
    // Is my role to `write_msg` (as opposed to `read_msg`)?
    should_write: bool,
    // Pre-shared key.
    psk: Option<SharedSecret>,
}

impl HandshakeState {
    /// Initializes a peer.
    ///
    /// * See [`patterns`](../patterns/index.html) for a list of available `HandshakePattern`s
    /// * `initiator = false` means the instance is for a responder.
    /// * `prologue` is a byte string record of anything that happened prior the Noise handshake.
    ///    These bytes are immediately hashed into the symmetric state
    /// * The ephemeral keypairs are mandatory for all handshake patterns.
    ///   the function returns a handshakeState object.
    pub fn new(
        handshake_pat: HandshakePattern,
        initiator: bool,
        prologue: Box<[u8]>,
        ephemeral_secret: Option<StaticSecret>,
        static_secret: Option<StaticSecret>,
        remote_ephemeral: Option<PublicKey>,
        remote_static: Option<PublicKey>,
        psk: Option<SharedSecret>,
    ) -> HandshakeState {
        let proto = format!(
            "Noise_{}_25519_STROBEv{}",
            handshake_pat.name, STROBE_VERSION
        );
        let mut symm_state = SymmetricState::new(proto.as_bytes());
        symm_state.mix_hash(&prologue);

        let message_pats = VecDeque::from(handshake_pat.message_pats.to_vec());
        let should_write = initiator;

        let ephemeral_public = ephemeral_secret.as_ref().map(PublicKey::from);
        let static_public = static_secret.as_ref().map(PublicKey::from);

        let mut h = HandshakeState {
            symm_state,
            ephemeral_secret,
            ephemeral_public,
            static_secret,
            static_public,
            remote_ephemeral,
            remote_static,
            initiator,
            message_pats,
            should_write,
            psk,
        };

        h.initialize(&handshake_pat.pre_message_pats);
        h
    }

    fn e(&mut self) -> StaticSecret {
        self.ephemeral_secret.clone().expect("ephermal secret")
    }

    fn s(&mut self) -> StaticSecret {
        self.static_secret.clone().expect("static secret")
    }

    fn e_pub(&self) -> &PublicKey {
        self.static_public.as_ref().unwrap()
    }

    fn s_pub(&self) -> &PublicKey {
        self.static_public.as_ref().unwrap()
    }

    fn re(&self) -> &PublicKey {
        self.remote_ephemeral.as_ref().unwrap()
    }

    fn rs(&self) -> &PublicKey {
        self.remote_static.as_ref().unwrap()
    }

    // Calls mix_hash() once for each public key listed in the pre-messages from handshake_pattern,
    // with the specified public key as input (see Section 7 for an explanation of pre-messages).
    // If both initiator and responder have pre-messages, the initiator's public keys are hashed
    // first.
    fn initialize(&mut self, pre_message_pats: &PreMessagePatternPair) {
        // Initiator pre-message pattern
        for &token in pre_message_pats.initiator {
            if let Token::S = token {
                if self.initiator {
                    let s = self.s_pub().as_bytes().to_vec();
                    self.symm_state.mix_hash(&s);
                } else {
                    let rs = self.rs().as_bytes().to_vec();
                    self.symm_state.mix_hash(&rs);
                }
            } else {
                panic!("disco: Token of pre-message not supported: {:?}", token)
            }
        }

        // Responder pre-message pattern
        for &token in pre_message_pats.responder {
            if let Token::S = token {
                if self.initiator {
                    let rs = self.rs().as_bytes().to_vec();
                    self.symm_state.mix_hash(&rs);
                } else {
                    let s = self.s_pub().as_bytes().to_vec();
                    self.symm_state.mix_hash(&s);
                }
            } else {
                panic!("disco: Pre-message token not supported: {:?}", token)
            }
        }
    }

    // Returns (payload, is_handshake_complete)
    pub fn write_msg(&mut self, payload: Vec<u8>) -> Result<(Vec<u8>, bool), DiscoWriteError> {
        if !self.should_write {
            panic!("disco: Call to write_msg when it is not our turn to write");
        }

        if payload.len() > MAX_PLAINTEXT_SIZE {
            return Err(DiscoWriteError::TooLongErr);
        }

        // If there are no patterns left or the next pattern is length 0, i.e., if we can't
        // continue, then panic
        if self
            .message_pats
            .get(0)
            .map(|pat| pat.len() == 0)
            .unwrap_or(true)
        {
            panic!("disco: No more tokens or message patterns to write");
        }

        // This will be our output
        let mut msg_buf = Vec::new();

        // We can unwrap because we just checked message_pats.len() != 0
        let pat = self.message_pats.pop_front().unwrap();
        for &token in pat {
            match token {
                Token::E => {
                    let e = StaticSecret::new(&mut rand::rngs::OsRng);
                    let e_pub = PublicKey::from(&e);

                    msg_buf.extend_from_slice(e_pub.as_bytes());
                    self.symm_state.mix_hash(e_pub.as_bytes());
                    if self.psk.is_some() {
                        self.symm_state.mix_key(e_pub.as_bytes());
                    }

                    self.ephemeral_secret = Some(e);
                    self.ephemeral_public = Some(e_pub);
                }

                Token::S => {
                    let s = self.s_pub().as_bytes().to_vec();
                    let ct = self.symm_state.encrypt_and_hash(&s);
                    msg_buf.extend(ct);
                }

                Token::EE => {
                    let ee = self.e().diffie_hellman(self.re());
                    self.symm_state.mix_key(ee.as_bytes());
                }

                Token::ES => {
                    if self.initiator {
                        let es = self.e().diffie_hellman(self.rs());
                        self.symm_state.mix_key(es.as_bytes());
                    } else {
                        let se = self.s().diffie_hellman(self.re());
                        self.symm_state.mix_key(se.as_bytes());
                    }
                }

                Token::SE => {
                    if self.initiator {
                        let se = self.s().diffie_hellman(self.re());
                        self.symm_state.mix_key(se.as_bytes());
                    } else {
                        let es = self.e().diffie_hellman(self.rs());
                        self.symm_state.mix_key(es.as_bytes());
                    }
                }

                Token::SS => {
                    let ss = self.s().diffie_hellman(self.rs());
                    self.symm_state.mix_key(ss.as_bytes());
                }

                Token::Psk => {
                    let psk = self
                        .psk
                        .as_ref()
                        .expect("disco: In processing psk token, no preshared key is set");
                    self.symm_state.mix_key_and_hash(psk.as_bytes());
                }
            }
        }

        let ct = self.symm_state.encrypt_and_hash(&payload);
        msg_buf.extend(ct);

        // Next time it's our turn to read
        self.should_write = false;

        // If there's nothing left to read, say we're ready to split()
        if self.message_pats.len() == 0 {
            Ok((msg_buf, true))
        } else {
            Ok((msg_buf, false))
        }
    }

    // Returns (payload, is_handshake_complete)
    pub fn read_msg(&mut self, mut msg: Vec<u8>) -> Result<(Vec<u8>, bool), DiscoReadError> {
        if self.should_write {
            panic!("disco: Call to read_msg when it is not our turn to read");
        }

        if msg.len() > MAX_PLAINTEXT_SIZE {
            return Err(DiscoReadError::TooLongErr);
        }

        // If there are no patterns left or the next pattern is length 0, i.e., if we can't
        // continue, then panic
        if self
            .message_pats
            .get(0)
            .map(|pat| pat.len() == 0)
            .unwrap_or(true)
        {
            panic!("disco: No more tokens or message patterns to write");
        }

        // We can unwrap because we just checked message_pats.len() != 0
        let pat = self.message_pats.pop_front().unwrap();
        for &token in pat {
            match token {
                Token::E => {
                    if msg.len() < DH_SIZE {
                        return Err(DiscoReadError::ParseErr(
                            "disco: In processing e token, msg too short",
                        ));
                    }
                    // tmp holds the rest of the message, msg holds the pubkey
                    let tmp = msg.split_off(DH_SIZE);
                    let mut e = [0u8; KEY_SIZE];
                    e.copy_from_slice(&*msg);
                    self.remote_ephemeral = Some(PublicKey::from(e));
                    msg = tmp;
                }

                Token::S => {
                    let tag_size = if self.symm_state.is_keyed() {
                        TAG_SIZE
                    } else {
                        0
                    };
                    let len = msg.len();
                    if len < DH_SIZE + tag_size {
                        return Err(DiscoReadError::ParseErr(
                            "disco: In processing s token, msg too short",
                        ));
                    }
                    // tmp holds the rest of the message, msg holds the pubkey
                    let tmp = msg.split_off(DH_SIZE + tag_size);
                    let ct = msg;
                    msg = tmp;
                    let pt = self
                        .symm_state
                        .decrypt_and_hash(&ct)
                        .map_err(|_| DiscoReadError::AuthErr)?;
                    let mut s = [0u8; DH_SIZE];
                    s.copy_from_slice(&*pt);
                    self.remote_static = Some(PublicKey::from(s));
                }

                Token::EE => {
                    let ee = self.e().diffie_hellman(self.re());
                    self.symm_state.mix_key(ee.as_bytes());
                }

                Token::ES => {
                    if self.initiator {
                        let es = self.e().diffie_hellman(self.rs());
                        self.symm_state.mix_key(es.as_bytes());
                    } else {
                        let se = self.s().diffie_hellman(self.re());
                        self.symm_state.mix_key(se.as_bytes());
                    }
                }

                Token::SE => {
                    if self.initiator {
                        let se = self.s().diffie_hellman(self.re());
                        self.symm_state.mix_key(se.as_bytes());
                    } else {
                        let es = self.e().diffie_hellman(self.rs());
                        self.symm_state.mix_key(es.as_bytes());
                    }
                }

                Token::SS => {
                    let ss = self.s().diffie_hellman(self.rs());
                    self.symm_state.mix_key(ss.as_bytes());
                }

                Token::Psk => {
                    let psk = self
                        .psk
                        .as_ref()
                        .expect("disco: In processing psk token, no preshared key is set");
                    self.symm_state.mix_key_and_hash(psk.as_bytes());
                }
            }
        }

        let pt = self
            .symm_state
            .decrypt_and_hash(&msg)
            .map_err(|_| DiscoReadError::AuthErr)?;

        // Next time it's our turn to read
        self.should_write = true;

        // If there's nothing left to read, say we're ready to split()
        if self.message_pats.len() == 0 {
            Ok((pt, true))
        } else {
            Ok((pt, false))
        }
    }

    pub fn finalize(self) -> (Strobe, Strobe) {
        self.symm_state.split()
    }
}
