//! A rust implementation of the disco protocol.
#![deny(missing_docs)]
//#![deny(warnings)]

mod config;
mod constants;
mod handshake_state;
pub mod patterns;
mod session;
pub mod symmetric;
mod symmetric_state;

pub use config::{ConfigBuilder, PublicKeyVerifier};
pub use handshake_state::Role;
pub use session::Session;
pub use x25519_dalek as x25519;
