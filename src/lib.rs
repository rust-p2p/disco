//! A rust implementation of the disco protocol.
#![deny(missing_docs)]
#![deny(warnings)]

mod builder;
mod constants;
mod handshake_state;
pub mod patterns;
pub mod symmetric;
mod symmetric_state;
mod transport_state;

pub use builder::SessionBuilder;
pub use constants::MAX_MSG_LEN;
pub use handshake_state::ReadError;
pub use x25519_dalek as x25519;
