//! A rust implementation of the disco protocol.
#![deny(missing_docs)]
#![deny(warnings)]
#![allow(unused)]

mod apis;
mod config;
mod disco;
pub mod patterns;
pub mod symmetric;

pub use apis::Session;
pub use config::{ConfigBuilder, PublicKeyVerifier, Role};
pub use x25519_dalek as x25519;
