/// Checks if, at some point in the protocol, the peer needs to verify the other peer static public
/// key and if the peer needs to provide a proof for its static public key.

use std::error;
use std::fmt;

use asymmetric::DH_SIZE;
use config::Config;
use disco::{DiscoReadError, DiscoWriteError, HandshakeState, KEY_SIZE};

use strobe_rs::Strobe;
use take_mut;

#[derive(Debug)]
enum ReqError {
    ErrNoPubKeyVerifier,
    ErrNoProof,
    ErrNoPsk,
}

impl error::Error for ReqError {
    fn description(&self) -> &str {
        match self {
            ReqError::ErrNoPubKeyVerifier => "disco: no pubkey verifier set in Config",
            ReqError::ErrNoProof => "disco: no pubkey proof set in Config",
            ReqError::ErrNoPsk => "noise: psk not provided for NNpsk2 handshake pattern",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl fmt::Display for ReqError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use std::error::Error;
        f.write_str(self.description())
    }
}

fn check_requirements<F>(is_client: bool, config: &Config<F>) -> Result<(), ReqError>
    where F: Fn(&[u8; DH_SIZE], &[u8]) -> bool
{
    match config.handshake_pat.name {
        b"NX" | b"KX" | b"XX" | b"IX" => {
            if is_client && config.pub_key_verifier.is_none() {
                return Err(ReqError::ErrNoPubKeyVerifier);
            }
            else if !is_client && config.static_pub_key_proof.is_none() {
                return Err(ReqError::ErrNoProof);
            }
        }

        b"XN" | b"XK" | b"XX" | b"X" | b"IN" | b"IK" | b"IX" => {
            if is_client && config.static_pub_key_proof.is_none() {
                return Err(ReqError::ErrNoProof);
            }
            else if !is_client && config.pub_key_verifier.is_none() {
                return Err(ReqError::ErrNoPubKeyVerifier);
            }
        }

        b"NNPsk2" => {
            if config.preshared_key.is_none() {
                return Err(ReqError::ErrNoPsk);
            }
        }

        _ => panic!("disco: unknown handshake type: {:?}", config.handshake_pat.name),
    }

    Ok(())
}

enum SessionState {
    Handshake(HandshakeState),
    // Transport is (rx, tx) of CipherState
    Transport(Strobe, Strobe),
}

struct Session<F: Fn(&[u8; DH_SIZE], &[u8]) -> bool> {
    config: Config<F>,
    state: SessionState,
    initiator: bool,
}

impl<F: Fn(&[u8; DH_SIZE], &[u8]) -> bool> Session<F> {
    pub fn read_message(&mut self, input: Vec<u8>) -> Result<Vec<u8>, DiscoReadError> {
        let mut just_completed_handshake = false;
        let res = match self.state {
            SessionState::Transport(ref mut rx, _) => rx.recv_enc(input, None, false),
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

    pub fn write_message(&mut self, payload: Vec<u8>) -> Result<Vec<u8>, DiscoWriteError> {
        let mut just_completed_handshake = false;
        let payload = match self.state {
            SessionState::Transport(_, ref mut tx) => tx.send_enc(payload, None, false),
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

    pub fn rekey_rx(&mut self) {
        if let SessionState::Transport(ref mut rx, _) = self.state {
            rx.ratchet(16, None, false);
        } else {
            panic!("disco: Attempted to re-key before handshake was finished");
        }
    }

    pub fn rekey_tx(&mut self) {
        if let SessionState::Transport(_, ref mut tx) = self.state {
            tx.ratchet(16, None, false);
        } else {
            panic!("disco: Attempted to re-key before handshake was finished");
        }
    }

    fn to_transport_phase(&mut self) {
        let initiator = self.initiator;
        // TODO: Remove dependency on take_mut if possible
        take_mut::take(&mut self.state, |st| {
            if let SessionState::Handshake(mut hs_st) = st {
                let (s_init, s_resp) = hs_st.finalize();
                // Remember, this is (rx, tx)
                if initiator {
                    SessionState::Transport(s_resp, s_init)
                } else {
                    SessionState::Transport(s_init, s_resp)
                }
            } else {
              st
            }
        });
    }

    pub fn set_psk(&mut self, key: [u8; KEY_SIZE]) {
        self.config.preshared_key = Some(key);
    }
}
