//! Transport phase of a Noise session.
use crate::constants::{MAX_MSG_LEN, TAG_LEN};
use crate::handshake_state::{PanicOption, ReadError};
use strobe_rs::Strobe;

/// A state machine encompassing the transport phase of a Noise session.
pub struct TransportState {
    pub(crate) tx: PanicOption<Strobe>,
    pub(crate) rx: PanicOption<Strobe>,
}

impl TransportState {
    /// Encrypts and authenticates a message.
    pub fn write_message(&mut self, pt: &[u8]) -> Vec<u8> {
        assert!(pt.len() < MAX_MSG_LEN - TAG_LEN);
        let mut ct = Vec::with_capacity(pt.len() + TAG_LEN);
        ct.extend_from_slice(pt);
        self.tx.send_enc(&mut ct[..pt.len()], false);
        ct.extend_from_slice(&[0u8; TAG_LEN]);
        self.tx.send_mac(&mut ct[pt.len()..], false);
        ct
    }

    /// Decrypts and authenticates a message.
    pub fn read_message(&mut self, ct: &[u8]) -> Result<Vec<u8>, ReadError> {
        assert!(ct.len() < MAX_MSG_LEN);
        if ct.len() < TAG_LEN {
            return Err(ReadError::AuthError);
        }
        let pt_len = ct.len() - TAG_LEN;
        let mut pt = Vec::with_capacity(pt_len);
        pt.extend_from_slice(&ct[..pt_len]);
        self.rx.recv_enc(&mut pt, false);
        let mut mac = ct[pt_len..].to_vec();
        self.rx.recv_mac(&mut mac, false)?;
        Ok(pt)
    }

    /// Rekeys the incoming channel.
    pub fn rekey_incoming(&mut self) {
        self.rx.ratchet(16, false);
    }

    /// Rekeys the outgoing channel.
    pub fn rekey_outgoing(&mut self) {
        self.tx.ratchet(16, false);
    }
}
