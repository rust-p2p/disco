//! Checks if, at some point in the protocol, the peer needs to verify the
//! other peer static public key and if the peer needs to provide a proof for
//! its static public key.
use crate::config::Config;
use crate::handshake_state::{HandshakeState, ReadError, Role};
use strobe_rs::Strobe;

enum SessionState {
    Handshake { h: HandshakeState, role: Role },
    Transport { rx: Strobe, tx: Strobe },
}

/// State machine for a noise session.
pub struct Session {
    state: SessionState,
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
        let h = HandshakeState::new(
            handshake_pattern,
            role,
            &prologue,
            Some(secret),
            None,
            remote_public,
            None,
            preshared_secret,
        );
        let state = SessionState::Handshake { h, role };
        Self { state }
    }

    /// Reads a message.
    pub fn read_message(&mut self, ct: &[u8]) -> Result<Vec<u8>, ReadError> {
        match self.state {
            SessionState::Transport { ref mut rx, tx: _ } => {
                let mut pt = ct.to_vec();
                rx.recv_enc(&mut pt, false);
                Ok(pt)
            }
            SessionState::Handshake { ref mut h, role: _ } => {
                let pt = h.read_message(ct)?;
                if h.is_handshake_complete() {
                    self.to_transport_phase();
                }
                Ok(pt)
            }
        }
    }

    /// Writes a message.
    pub fn write_message(&mut self, pt: &[u8]) -> Vec<u8> {
        match self.state {
            SessionState::Transport { ref mut tx, rx: _ } => {
                let mut ct = pt.to_vec();
                tx.send_enc(&mut ct, false);
                ct
            }
            SessionState::Handshake { ref mut h, role: _ } => {
                let ct = h.write_message(pt);
                if h.is_handshake_complete() {
                    self.to_transport_phase();
                }
                ct
            }
        }
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
        take_mut::take(&mut self.state, |state| {
            if let SessionState::Handshake { h, role } = state {
                let (init, resp) = h.finalize();
                match role {
                    Role::Initiator => SessionState::Transport { rx: resp, tx: init },
                    Role::Responder => SessionState::Transport { rx: init, tx: resp },
                }
            } else {
                state
            }
        });
    }
}
