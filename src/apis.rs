//! Checks if, at some point in the protocol, the peer needs to verify the
//! other peer static public key and if the peer needs to provide a proof for
//!  its static public key.
use crate::config::{Config, Role};
use crate::disco::{DiscoReadError, DiscoWriteError, HandshakeState};

use failure::Fail;
use strobe_rs::Strobe;
use take_mut;

#[derive(Debug, Fail)]
enum ReqError {
    #[fail(display = "disco: no public key verifier set in config.")]
    ErrNoPubKeyVerifier,
    #[fail(display = "disco: no public key proof set in config.")]
    ErrNoProof,
    #[fail(display = "noise: psk not provided for NNpsk2 handshake pattern.")]
    ErrNoPsk,
}

enum SessionState {
    Handshake(HandshakeState),
    Transport { rx: Strobe, tx: Strobe },
}

/// State machine for a noise session.
pub struct Session {
    state: SessionState,
    role: Role,
}

impl Session {
    /// Creates a new session from a config.
    pub fn new(config: Config) -> Self {
        let Config {
            handshake_pattern,
            role,
            secret,
            remote_public,
            prologue,
            public_key_proof: _,
            public_key_verifier: _,
            preshared_secret,
            half_duplex: _,
        } = config;
        let hstate = HandshakeState::new(
            handshake_pattern,
            role == Role::Initiator,
            prologue,
            None,
            Some(secret),
            None,
            remote_public,
            preshared_secret,
        );
        let state = SessionState::Handshake(hstate);
        Self { state, role }
    }

    /// Reads a message.
    pub fn read_message(&mut self, mut input: Vec<u8>) -> Result<Vec<u8>, DiscoReadError> {
        let mut just_completed_handshake = false;
        let res = match self.state {
            SessionState::Transport { ref mut rx, tx: _ } => {
                rx.recv_enc(&mut input, false);
                input
            }
            SessionState::Handshake(ref mut hs_st) => {
                let (out, done) = hs_st.read_msg(input)?;
                just_completed_handshake = done;
                out
            }
        };

        if just_completed_handshake {
            self.to_transport_phase();
        }

        Ok(res)
    }

    /// Writes a message.
    pub fn write_message(&mut self, mut payload: Vec<u8>) -> Result<Vec<u8>, DiscoWriteError> {
        let mut just_completed_handshake = false;
        let payload = match self.state {
            SessionState::Transport { ref mut tx, rx: _ } => {
                tx.send_enc(&mut payload, false);
                payload
            }
            SessionState::Handshake(ref mut hs_st) => {
                let (out, done) = hs_st.write_msg(payload)?;
                just_completed_handshake = done;
                out
            }
        };

        if just_completed_handshake {
            self.to_transport_phase();
        }

        Ok(payload)
    }

    /// Parties might wish to periodically update their cipherstate keys to
    /// ensure that a compromise of cipherstate keys will not decrypt older
    /// messages.
    pub fn rekey_rx(&mut self) {
        if let SessionState::Transport { ref mut rx, tx: _ } = self.state {
            rx.ratchet(16, false);
        } else {
            panic!("disco: Attempted to re-key before handshake was finished");
        }
    }

    /// Parties might wish to periodically update their cipherstate keys to
    /// ensure that a compromise of cipherstate keys will not decrypt older
    /// messages.
    pub fn rekey_tx(&mut self) {
        if let SessionState::Transport { ref mut tx, rx: _ } = self.state {
            tx.ratchet(16, false);
        } else {
            panic!("disco: Attempted to re-key before handshake was finished");
        }
    }

    fn to_transport_phase(&mut self) {
        let role = self.role;
        // TODO: Remove dependency on take_mut if possible
        take_mut::take(&mut self.state, |st| {
            if let SessionState::Handshake(hs_st) = st {
                let (s_init, s_resp) = hs_st.finalize();
                match role {
                    Role::Initiator => SessionState::Transport {
                        rx: s_resp,
                        tx: s_init,
                    },
                    Role::Responder => SessionState::Transport {
                        rx: s_init,
                        tx: s_resp,
                    },
                }
            } else {
                st
            }
        });
    }
}
