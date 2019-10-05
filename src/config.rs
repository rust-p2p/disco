use crate::asymmetric::{KeyPair, DH_SIZE};
use crate::disco::KEY_SIZE;
use crate::patterns::HandshakePattern;

// The following constants represent the details of this implementation of the Noise specification.
const DISCO_DRAFT_VERSION: &'static [u8] = b"3";
const NOISE_DH: &'static [u8] = b"25519";

// The following constants are taken directly from the Noise specification.
pub(crate) const NOISE_MAX_MSG_SIZE: usize = 65535;
pub(crate) const NOISE_TAG_SIZE: usize = 16;
pub(crate) const NOISE_MAX_PLAINTEXT_SIZE: usize = NOISE_MAX_MSG_SIZE - NOISE_TAG_SIZE;

pub struct Config<F: Fn(&[u8; DH_SIZE], &[u8]) -> bool> {
    // The type of Noise protocol that the client and the server will go through.
    pub(crate) handshake_pat: HandshakePattern,
    // The current peer's keypair.
    pub(crate) keypair: KeyPair,
    // The other peer's public key.
    pub(crate) remote_pub_key: [u8; DH_SIZE],
    // Any messages that the client and the server previously exchanged in clear
    pub(crate) prologue: Vec<u8>,
    // If the chosen handshake pattern requires the current peer to send a static public key as
    // part of the handshake, this proof over the key is mandatory in order for the other peer to
    // verify the current peer's key.
    pub(crate) static_pub_key_proof: Option<Vec<u8>>,
    // If the chosen handshake pattern requires the remote peer to send an unknown static public
    // key as part of the handshake, this callback is mandatory in order to validate it.
    pub(crate) pub_key_verifier: Option<F>,
    // A pre-shared key for handshake patterns including a `psk` token.
    pub(crate) preshared_key: Option<[u8; KEY_SIZE]>,
    // By default a noise protocol is full-duplex, meaning that both the client
    // and the server can write on the channel at the same time. Setting this value
    // to true will require the peers to write and read in turns. If this requirement
    // is not respected by the application, the consequences could be catastrophic.
    pub(crate) half_duplex: bool,
}
