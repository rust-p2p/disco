//! This module contains the data pertaining to Noise handshake patterns. For more information on
//! these patterns, consult the
//! [Noise specification](https://noiseprotocol.org/noise.html#handshake-patterns).

use std::fmt;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Token {
    E,
    S,
    ES,
    SE,
    SS,
    EE,
    Psk,
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use self::Token::*;

        let tok_s = match self {
            &E   => "e",
            &S   => "s",
            &ES  => "es",
            &SE  => "se",
            &SS  => "ss",
            &EE  => "ee",
            &Psk => "psk"
        };
        f.write_str(tok_s)
    }
}


pub(crate) type MessagePattern = &'static [Token];

#[derive(Eq, PartialEq)]
pub(crate) struct PreMessagePatternPair {
    pub initiator: MessagePattern,
    pub responder: MessagePattern,
}

#[derive(Eq, PartialEq)]
pub struct HandshakePattern {
    pub(crate) name: &'static [u8],
    pub(crate) pre_message_pats: PreMessagePatternPair,
    pub(crate) message_pats: &'static [MessagePattern],
}

// 7.2 - One-way Patterns

/// A one-way pattern where a client can send data to a server with a known static key. The server
/// can only receive data and cannot reply back.
pub const NOISE_N: HandshakePattern = HandshakePattern {
    name: b"N",
    pre_message_pats: PreMessagePatternPair {
        initiator: &[],
        responder: &[Token::S],
    },
    message_pats: &[
        &[Token::E, Token::ES],
        &[],
    ],
};

/// A one-way pattern where a client can send data to a server with a known static key. The server
/// can only receive data and cannot reply back. The server authenticates the client via a known
/// key.
pub const NOISE_K: HandshakePattern = HandshakePattern {
    name: b"K",
    pre_message_pats: PreMessagePatternPair {
        initiator: &[Token::S],
        responder: &[Token::S],
    },
    message_pats: &[
        &[Token::E, Token::ES, Token::SS],
        &[],
    ],
};

/// A one-way pattern where a client can send data to a server with a known static key. The server
/// can only receive data and cannot reply back. The server authenticates the client via a key
/// transmitted as part of the handshake.
pub const NOISE_X: HandshakePattern = HandshakePattern {
    name: b"X",
    pre_message_pats: PreMessagePatternPair {
        initiator: &[],
        responder: &[Token::S],
    },
    message_pats: &[
        &[Token::E, Token::ES, Token::S, Token::SS],
        &[],
    ],
};

// 7.3 - Interactive pats

/// A pattern where both the client static key and the server static key are known.
pub const NOISE_KK: HandshakePattern = HandshakePattern {
    name: b"KK",
    pre_message_pats: PreMessagePatternPair {
        initiator: &[Token::S],
        responder: &[Token::S],
    },
    message_pats: &[
        &[Token::E, Token::ES, Token::SS],
        &[Token::E, Token::EE, Token::SE],
    ],
};
