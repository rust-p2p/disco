//! A rust implementation of the disco protocol.
#![deny(missing_docs)]
#![deny(warnings)]

mod builder;
mod constants;
mod error;
mod handshake_state;
mod keypair;
mod patterns;
mod stateless_transport_state;
pub mod symmetric;
mod symmetric_state;
mod transport_state;

pub use builder::SessionBuilder;
pub use constants::{MAX_MSG_LEN, TAG_LEN};
pub use ed25519_dalek as ed25519;
pub use error::ReadError;
pub use stateless_transport_state::StatelessTransportState;
pub use symmetric::DiscoHash;
pub use transport_state::TransportState;
pub use x25519_dalek as x25519;
