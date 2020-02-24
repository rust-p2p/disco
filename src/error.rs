use std::fmt::{Display, Formatter, Result};

/// Read error returned by `read_message`.
#[derive(Debug)]
pub enum ReadError {
    /// Message is invalid.
    InvalidMessage,
    /// Message authentication failed.
    AuthError,
    /// Invalid signature.
    SignatureError,
}

impl Display for ReadError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let msg = match self {
            ReadError::InvalidMessage => "Invalid message",
            ReadError::AuthError => "Invalid mac",
            ReadError::SignatureError => "Invalid signature",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for ReadError {}

impl From<strobe_rs::AuthError> for ReadError {
    fn from(_: strobe_rs::AuthError) -> Self {
        Self::AuthError
    }
}

impl From<crate::ed25519::SignatureError> for ReadError {
    fn from(_: crate::ed25519::SignatureError) -> Self {
        Self::SignatureError
    }
}

/// Pattern error.
#[derive(Debug)]
pub enum PatternError {
    UnsupportedHandshakeType,
    UnsupportedModifier,
    InvalidPsk,
}

impl Display for PatternError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let msg = match self {
            PatternError::UnsupportedHandshakeType => "Unsupported handshake type",
            PatternError::UnsupportedModifier => "Unsupported modifier",
            PatternError::InvalidPsk => "Invalid psk",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for PatternError {}
