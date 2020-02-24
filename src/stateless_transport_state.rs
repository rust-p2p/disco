//! Transport phase of a Noise session.
use crate::constants::{MAX_MSG_LEN, TAG_LEN};
use crate::error::ReadError;
use crate::handshake_state::PanicOption;
use strobe_rs::Strobe;

/// A state machine encompassing the transport phase of a Noise session.
pub struct StatelessTransportState {
    pub(crate) tx: PanicOption<Strobe>,
    pub(crate) rx: PanicOption<Strobe>,
}

impl StatelessTransportState {
    /// Encrypts and authenticates a message using it's sequence number.
    ///
    /// To avoid messages being replayed, the caller must ensure that the nonce
    /// is never reused, and that the outgoing channel is rekeyed if the nonce
    /// equals u64::MAX.
    pub fn write_message(&self, nonce: u64, pt: &mut [u8]) -> [u8; TAG_LEN] {
        assert!(pt.len() < MAX_MSG_LEN - TAG_LEN);
        let mut tx = self.tx.clone();
        tx.ad(&nonce.to_be_bytes()[..], false);
        tx.send_enc(pt, false);
        let mut tag = [0u8; TAG_LEN];
        tx.send_mac(&mut tag, false);
        tag
    }

    /// Decrypts and authenticates a message using it's sequence number.
    ///
    /// To avoid messages being replayed, the caller must ensure that the nonce
    /// is never reused, and that the incoming channel is rekeyed if the nonce
    /// equals u64::MAX.
    pub fn read_message(
        &self,
        nonce: u64,
        ct: &mut [u8],
        tag: [u8; TAG_LEN],
    ) -> Result<(), ReadError> {
        assert!(ct.len() < MAX_MSG_LEN);
        let mut rx = self.rx.clone();
        rx.ad(&nonce.to_be_bytes()[..], false);
        rx.recv_enc(ct, false);
        let mut mac = tag.clone();
        rx.recv_mac(&mut mac[..], false)?;
        Ok(())
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
