//! Implementation of the SymmetricState.
use crate::config::{KEY_SIZE, TAG_SIZE};
use strobe_rs::{AuthError, SecParam, Strobe};

/// 5.2. The SymmetricState object.
pub struct SymmetricState {
    /// Strobe state.
    strobe: Strobe,
    /// Is true after a key has been mixed into the state.
    is_keyed: bool,
}

impl SymmetricState {
    /// Takes an arbitrary-length `protocol_name` byte sequence and initializes
    /// strobe.
    pub fn new(protocol_name: &[u8]) -> SymmetricState {
        let strobe = Strobe::new(protocol_name, SecParam::B128);
        SymmetricState {
            strobe,
            is_keyed: false,
        }
    }

    /// Is keyed returns true after a key has been mixed into the symmetric
    /// state.
    pub fn is_keyed(&self) -> bool {
        self.is_keyed
    }

    /// Mixes a key into the symmetric state.
    pub fn mix_key(&mut self, key: &[u8]) {
        assert!(key.len() == KEY_SIZE);
        self.strobe.ad(key, false);
        self.is_keyed = true;
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
        if self.is_keyed {
            let mut ct = Vec::with_capacity(pt.len() + TAG_SIZE);
            ct.extend_from_slice(pt);
            self.strobe.send_enc(&mut ct[..pt.len()], false);
            ct.extend_from_slice(&[0u8; TAG_SIZE]);
            self.strobe.send_mac(&mut ct[pt.len()..], false);
            ct
        } else {
            pt.to_vec()
        }
    }

    /// Returns the plaintext of an authenticated ciphertext message.
    pub fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>, AuthError> {
        if self.is_keyed {
            if ct.len() < TAG_SIZE {
                return Err(AuthError);
            }
            let pt_len = ct.len() - TAG_SIZE;
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
    ///
    /// TODO: 11.3. Rekey
    /// TODO: 11.4. Out-of-order transport messages
    /// TODO: 11.5. Half-duplex protocols
    pub fn split(self) -> (Strobe, Strobe) {
        let mut s1 = self.strobe.clone();
        s1.ad(b"initiator", false);
        s1.ratchet(KEY_SIZE, false);

        let mut s2 = self.strobe;
        s2.ad(b"responder", false);
        s2.ratchet(KEY_SIZE, false);

        (s1, s2)
    }

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
        let mut buf = vec![0u8; KEY_SIZE];
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
