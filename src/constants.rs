//! Constants used by this crate.
pub const KEY_LEN: usize = 32;
pub const DH_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

/// Tag length defined in the Noise specification.
pub const TAG_LEN: usize = 16;
/// Maximum message length defined in the Noise specification.
pub const MAX_MSG_LEN: usize = 65535;
