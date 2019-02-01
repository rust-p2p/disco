use rand::{thread_rng, RngCore};
use strobe_rs::{SecParam, Strobe};
pub use strobe_rs::AuthError;

pub const NONCE_SIZE: usize = 192 / 8;
pub(crate) const TAG_SIZE: usize = 16;
const ERR_KEY_TOO_SHORT: &'static str =
    "disco: using a key smaller than 128-bit (16 bytes) has security consequences";

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
        if bytes.len() < TAG_SIZE {
            None
        }
        else {
            // Interpret the input as mac || pt
            let pt = bytes.split_off(TAG_SIZE);
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
        if bytes.len() < TAG_SIZE + NONCE_SIZE {
            None
        }
        else {
            // Interpret the input as mac || nonce || ct
            let mut rest = bytes.split_off(TAG_SIZE);
            let mac = bytes;
            let rest2 = rest.split_off(NONCE_SIZE);
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
/// h.write("foo bar".as_bytes().to_vec());
/// # }
/// ```
/// is equivalent to
/// ```rust
/// # extern crate disco_rs;
/// # use disco_rs::symmetric::DiscoHash;
/// # fn main() {
/// # let mut h = DiscoHash::new(32);
/// h.write("foo".as_bytes().to_vec());
/// h.write(" bar".as_bytes().to_vec());
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
        if output_len < 32 {
            panic!("disco: an output length smaller than 256-bit (32 bytes)\
                    has security consequences");
        }
        DiscoHash {
            strobe_ctx: Strobe::new("DiscoHash".as_bytes().to_vec(), SecParam::B128),
            initialized: false,
            output_len: output_len,
        }
    }

    /// Absorbs more data into the hash's state
    pub fn write(&mut self, input_data: Vec<u8>) {
        self.strobe_ctx.ad(input_data, None, self.initialized);
        self.initialized = true
    }

    /// Reads the output from the hash. This affects the internal state, so reading will consume
    /// this `DiscoHash` instance. If you want to write and read more, you can clone this instance.
    pub fn sum(mut self) -> Vec<u8> {
        self.strobe_ctx.prf(self.output_len, None, false)
    }
}

/// Hashes an input of any length and obtain an output of length greater or equal to
/// 256 bits (32 bytes).
///
/// Panics when `output_len < 32`.
pub fn hash(input_data: Vec<u8>, output_len: usize) -> Vec<u8> {
    let mut h = DiscoHash::new(output_len);
    h.write(input_data);
    h.sum()
}

/// Derives longer keys given an input key.
///
/// Panics when `input_key.len() < 16`.
pub fn derive_keys(input_key: Vec<u8>, output_len: usize) -> Vec<u8> {
    if input_key.len() < 16 {
        panic!("disco: deriving keys from a value smaller than 128-bit (16 bytes) has\
                security consequences")
    }

    let mut s = Strobe::new("DiscoKDF".as_bytes().to_vec(), SecParam::B128);
    s.ad(input_key, None, false);
    s.prf(output_len, None, false)
}

/// Returns an authenticated message in cleartext (not encrypted). You can later verify via the
/// [`verify_integrity`](fn.verify_integrity.html) function that the message has not been modified.
///
/// Panics when `key.len() < 16`.
pub fn protect_integrity(key: Vec<u8>, plaintext: Vec<u8>) -> AuthPlaintext {
    if key.len() < 16 {
        panic!(ERR_KEY_TOO_SHORT);
    }

    let mut s = Strobe::new("DiscoMAC".as_bytes().to_vec(), SecParam::B128);
    s.ad(key, None, false);
    s.ad(plaintext.clone(), None, false);
    let mac = s.send_mac(TAG_SIZE, None, false);

    AuthPlaintext {
        pt: plaintext,
        mac: mac,
    }
}

/// Unwraps an [`AuthPlaintext`](struct.AuthPlaintext.html) object and checks the MAC. On success,
/// returns the underlying plaintext. On error, returns [`AuthError`](struct.AuthError.html).
///
/// Panics when `key.len() < 16`.
pub fn verify_integrity(key: Vec<u8>, input: AuthPlaintext) -> Result<Vec<u8>, AuthError> {
    if key.len() < 16 {
        panic!(ERR_KEY_TOO_SHORT);
    }

    let AuthPlaintext { pt, mac } = input;
    let mut s = Strobe::new("DiscoMAC".as_bytes().to_vec(), SecParam::B128);
    s.ad(key, None, false);
    s.ad(pt.clone(), None, false);

    match s.recv_mac(mac, None, false) {
        Ok(_) => Ok(pt),
        Err(ae) => Err(ae)
    }
}

/// Encrypts and MACs a plaintext message with a key of any size greater than 128 bits (16 bytes).
pub fn encrypt(key: Vec<u8>, plaintext: Vec<u8>) -> AuthCiphertext {
    if key.len() < 16 {
        panic!(ERR_KEY_TOO_SHORT);
    }

    let mut s = Strobe::new("DiscoAEAD".as_bytes().to_vec(), SecParam::B128);

    // Absorb the key
    s.ad(key, None, false);

    // Generate 192-bit nonce and absorb it
    let mut rng = thread_rng();
    let mut nonce = vec![0u8; NONCE_SIZE];
    rng.fill_bytes(nonce.as_mut_slice());
    s.ad(nonce.clone(), None, false);

    let ct = s.send_enc(plaintext, None, false);
    let mac = s.send_mac(TAG_SIZE, None, false);

    AuthCiphertext { mac, nonce, ct }
}

/// Decrypts and checks the MAC of an [`AuthCiphertext`](struct.AuthCiphertext.html) object, given
/// a key of any size greater than 128 bits (16 bytes).
pub fn decrypt(key: Vec<u8>, ciphertext: AuthCiphertext) -> Result<Vec<u8>, AuthError> {
    if key.len() < 16 {
        panic!(ERR_KEY_TOO_SHORT);
    }

    let AuthCiphertext { mac, nonce, ct } = ciphertext;
    let mut s = Strobe::new("DiscoAEAD".as_bytes().to_vec(), SecParam::B128);

    // Absorb the key and nonce
    s.ad(key, None, false);
    s.ad(nonce, None, false);

    let pt = s.recv_enc(ct, None, false);
    match s.recv_mac(mac, None, false) {
        Ok(_) => Ok(pt),
        Err(ae) => Err(ae),
    }
}
