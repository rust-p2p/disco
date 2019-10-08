//! Symmetric crypto primitives built with strobe.
use crate::constants::{NONCE_LEN, TAG_LEN};
use rand::{thread_rng, RngCore};
pub use strobe_rs::AuthError;
use strobe_rs::{SecParam, Strobe};

/// Represents plaintext with an associated MAC.
#[derive(Clone, Debug)]
pub struct AuthPlaintext {
    mac: Vec<u8>,
    pt: Vec<u8>,
}

impl AuthPlaintext {
    /// Dumps the bytes.
    ///
    /// NOTE: The MAC length is fixed in this implementation, so there is no immediate need to
    /// delimit the plaintext from the tag.
    pub fn into_bytes(self) -> Vec<u8> {
        // Output mac || pt
        let mut concatted = self.mac;
        concatted.extend(self.pt);
        concatted
    }

    /// Builds an `AuthPlaintext` struct from raw bytes. Returns `None` when the input is
    /// too short.
    pub fn from_bytes(mut bytes: Vec<u8>) -> Option<AuthPlaintext> {
        if bytes.len() < TAG_LEN {
            None
        } else {
            // Interpret the input as mac || pt
            let pt = bytes.split_off(TAG_LEN);
            let mac = bytes;
            Some(AuthPlaintext { mac, pt })
        }
    }
}

/// A ciphertext object with an associated MAC and nonce.
#[derive(Clone, Debug)]
pub struct AuthCiphertext {
    mac: Vec<u8>,
    nonce: Vec<u8>,
    ct: Vec<u8>,
}

impl AuthCiphertext {
    /// Dumps the bytes.
    ///
    /// NOTE: The MAC and nonce lengths are fixed in this implementation, so there is no immediate
    /// need to delimit the components.
    pub fn into_bytes(self) -> Vec<u8> {
        // Output mac || nonce || ct
        let mut concatted = self.mac;
        concatted.extend(self.nonce);
        concatted.extend(self.ct);
        concatted
    }

    /// Builds an `AuthCiphertext` struct from raw bytes. Returns `None` when the input is
    /// too short.
    pub fn from_bytes(mut bytes: Vec<u8>) -> Option<AuthCiphertext> {
        if bytes.len() < TAG_LEN + NONCE_LEN {
            None
        } else {
            // Interpret the input as mac || nonce || ct
            let mut rest = bytes.split_off(TAG_LEN);
            let mac = bytes;
            let rest2 = rest.split_off(NONCE_LEN);
            let nonce = rest;
            let ct = rest2;
            Some(AuthCiphertext { mac, nonce, ct })
        }
    }
}

/// An object for facilitating continuous hashing. General use is to call the `write` method a
/// bunch of times, and then call a final `sum`.
///
/// Input is streamed in, meaning that
/// ```rust
/// # extern crate disco_rs;
/// # use disco_rs::symmetric::DiscoHash;
/// # fn main() {
/// # let mut h = DiscoHash::new(32);
/// h.write(b"foo bar");
/// # }
/// ```
/// is equivalent to
/// ```rust
/// # extern crate disco_rs;
/// # use disco_rs::symmetric::DiscoHash;
/// # fn main() {
/// # let mut h = DiscoHash::new(32);
/// h.write(b"foo");
/// h.write(b" bar");
/// # }
/// ```
#[derive(Clone)]
pub struct DiscoHash {
    strobe_ctx: Strobe,
    initialized: bool,
    output_len: usize,
}

impl DiscoHash {
    /// Makes a new `DisocHash` object with the given digest size.
    ///
    /// Panics when `output_len < 32`.
    pub fn new(output_len: usize) -> DiscoHash {
        assert!(output_len >= 32);
        DiscoHash {
            strobe_ctx: Strobe::new(b"DiscoHash", SecParam::B128),
            initialized: false,
            output_len: output_len,
        }
    }

    /// Absorbs more data into the hash's state
    pub fn write(&mut self, input_data: &[u8]) {
        self.strobe_ctx.ad(input_data, self.initialized);
        self.initialized = true
    }

    /// Reads the output from the hash. This affects the internal state, so reading will consume
    /// this `DiscoHash` instance. If you want to write and read more, you can clone this instance.
    pub fn sum(mut self) -> Vec<u8> {
        let mut buf = vec![0u8; self.output_len];
        self.strobe_ctx.prf(&mut buf, false);
        buf
    }
}

/// Hashes an input of any length and obtain an output of length greater or equal to
/// 256 bits (32 bytes).
///
/// Panics when `output_len < 32`.
pub fn hash(input_data: &[u8], output_len: usize) -> Vec<u8> {
    let mut h = DiscoHash::new(output_len);
    h.write(input_data);
    h.sum()
}

/// Derives longer keys given an input key.
///
/// Panics when `input_key.len() < 16`.
pub fn derive_keys(input_key: &[u8], output_len: usize) -> Vec<u8> {
    assert!(input_key.len() >= 16);

    let mut s = Strobe::new(b"DiscoKDF", SecParam::B128);
    s.ad(input_key, false);
    let mut buf = vec![0u8; output_len];
    s.prf(&mut buf, false);
    buf
}

/// Returns an authenticated message in cleartext (not encrypted). You can later verify via the
/// [`verify_integrity`](fn.verify_integrity.html) function that the message has not been modified.
///
/// Panics when `key.len() < 16`.
pub fn protect_integrity(key: &[u8], plaintext: Vec<u8>) -> AuthPlaintext {
    assert!(key.len() >= 16);

    let mut s = Strobe::new(b"DiscoMAC", SecParam::B128);
    s.ad(key, false);
    s.ad(&plaintext, false);
    let mut mac = vec![0u8; TAG_LEN];
    s.send_mac(&mut mac, false);

    AuthPlaintext {
        pt: plaintext,
        mac: mac,
    }
}

/// Unwraps an [`AuthPlaintext`](struct.AuthPlaintext.html) object and checks the MAC. On success,
/// returns the underlying plaintext. On error, returns [`AuthError`](struct.AuthError.html).
///
/// Panics when `key.len() < 16`.
pub fn verify_integrity(key: &[u8], input: AuthPlaintext) -> Result<Vec<u8>, AuthError> {
    assert!(key.len() >= 16);

    let AuthPlaintext { pt, mut mac } = input;
    let mut s = Strobe::new(b"DiscoMAC", SecParam::B128);
    s.ad(key, false);
    s.ad(&pt, false);

    match s.recv_mac(&mut mac, false) {
        Ok(_) => Ok(pt),
        Err(ae) => Err(ae),
    }
}

/// Encrypts and MACs a plaintext message with a key of any size greater than 128 bits (16 bytes).
pub fn encrypt(key: &[u8], mut plaintext: Vec<u8>) -> AuthCiphertext {
    assert!(key.len() >= 16);

    let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);

    // Absorb the key
    s.ad(key, false);

    // Generate 192-bit nonce and absorb it
    let mut rng = thread_rng();
    let mut nonce = vec![0u8; NONCE_LEN];
    rng.fill_bytes(nonce.as_mut_slice());
    s.ad(&mut nonce, false);

    s.send_enc(&mut plaintext, false);
    let mut mac = vec![0u8; TAG_LEN];
    s.send_mac(&mut mac, false);

    AuthCiphertext {
        mac,
        nonce,
        ct: plaintext,
    }
}

/// Decrypts and checks the MAC of an [`AuthCiphertext`](struct.AuthCiphertext.html) object, given
/// a key of any size greater than 128 bits (16 bytes).
pub fn decrypt(key: &[u8], ciphertext: AuthCiphertext) -> Result<Vec<u8>, AuthError> {
    assert!(key.len() >= 16);

    let AuthCiphertext {
        mut mac,
        nonce,
        mut ct,
    } = ciphertext;
    let mut s = Strobe::new(b"DiscoAEAD", SecParam::B128);

    // Absorb the key and nonce
    s.ad(&key, false);
    s.ad(&nonce, false);

    s.recv_enc(&mut ct, false);
    match s.recv_mac(&mut mac, false) {
        Ok(_) => Ok(ct),
        Err(ae) => Err(ae),
    }
}
