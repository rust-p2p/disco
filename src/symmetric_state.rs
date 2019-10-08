//! Implementation of the SymmetricState.
use crate::constants::{KEY_LEN, TAG_LEN};
use strobe_rs::{AuthError, SecParam, Strobe};

/// 5.2. The SymmetricState object.
pub struct SymmetricState {
    /// Strobe state.
    strobe: Strobe,
    /// Is true after a key has been mixed into the state.
    has_key: bool,
}

impl SymmetricState {
    /// Takes an arbitrary-length `protocol_name` byte sequence and initializes
    /// strobe.
    pub fn new(protocol_name: &[u8]) -> SymmetricState {
        let strobe = Strobe::new(protocol_name, SecParam::B128);
        SymmetricState {
            strobe,
            has_key: false,
        }
    }

    /// Is keyed returns true after a key has been mixed into the symmetric
    /// state.
    pub fn has_key(&self) -> bool {
        self.has_key
    }

    /// Mixes a key into the symmetric state.
    pub fn mix_key(&mut self, key: &[u8]) {
        assert!(key.len() == KEY_LEN);
        self.strobe.ad(key, false);
        self.has_key = true;
    }

    /// Mixes arbitrary bytes into the symmetric state.
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.strobe.ad(data, false);
    }

    /// Used for handling pre-shared symmetric keys.
    pub fn mix_key_and_hash(&mut self, key: &[u8]) {
        self.strobe.ad(key, false);
    }

    /// Returns the authenticated ciphertext for a plaintext message.
    pub fn encrypt_and_hash(&mut self, pt: &[u8]) -> Vec<u8> {
        if self.has_key {
            let mut ct = Vec::with_capacity(pt.len() + TAG_LEN);
            ct.extend_from_slice(pt);
            self.strobe.send_enc(&mut ct[..pt.len()], false);
            ct.extend_from_slice(&[0u8; TAG_LEN]);
            self.strobe.send_mac(&mut ct[pt.len()..], false);
            ct
        } else {
            pt.to_vec()
        }
    }

    /// Returns the plaintext of an authenticated ciphertext message.
    pub fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>, AuthError> {
        if self.has_key {
            if ct.len() < TAG_LEN {
                return Err(AuthError);
            }
            let pt_len = ct.len() - TAG_LEN;
            let mut pt = Vec::with_capacity(pt_len);
            pt.extend_from_slice(&ct[..pt_len]);
            self.strobe.recv_enc(&mut pt, false);
            let mut mac = ct[pt_len..].to_vec();
            self.strobe.recv_mac(&mut mac, false)?;
            Ok(pt)
        } else {
            Ok(ct.to_vec())
        }
    }

    /// Returns a pair of CipherState objects for encrypting transport
    /// messages.
    pub fn split(self) -> (Strobe, Strobe) {
        let mut s1 = self.strobe.clone();
        s1.ad(b"initiator", false);
        s1.ratchet(16, false);

        let mut s2 = self.strobe;
        s2.ad(b"responder", false);
        s2.ratchet(16, false);

        (s1, s2)
    }

    /// Returns the handshake hash.
    pub fn get_handshake_hash(&mut self) -> Vec<u8> {
        let mut buf = vec![0u8; KEY_LEN];
        self.strobe.prf(&mut buf, false);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enc_dec() {
        let mut state1 = SymmetricState::new(b"test");
        let mut state2 = SymmetricState::new(b"test");
        state1.mix_key(&[0u8; 32]);
        state2.mix_key(&[0u8; 32]);
        let ct = state1.encrypt_and_hash(b"hello world");
        let pt = state2.decrypt_and_hash(&ct).unwrap();
        assert_eq!(&pt, b"hello world");
    }
}
