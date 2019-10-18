//! This module contains the data pertaining to Noise handshake patterns. For more information on
//! these patterns, consult the
//! [Noise specification](https://noiseprotocol.org/noise.html#handshake-patterns).
use failure::Fail;
use std::str::FromStr;
use HandshakePattern::*;

/// Role in the handshake process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Initiates the handshake.
    Initiator,
    /// Responds to the handshake.
    Responder,
}

/// The tokens which describe message patterns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    E,
    S,
    ES,
    SE,
    SS,
    EE,
    Psk,
    Sig,
}

pub type MessagePattern = &'static [Token];

/// Handshake protocol specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeTokens {
    pub(crate) name: &'static str,
    pub(crate) initiator: MessagePattern,
    pub(crate) responder: MessagePattern,
    pub(crate) handshake: &'static [MessagePattern],
}

/// Pattern error.
#[derive(Debug, Fail)]
pub enum PatternError {
    #[fail(display = "Unsupported handshake type")]
    UnsupportedHandshakeType,
    #[fail(display = "Unsupported modifier")]
    UnsupportedModifier,
    #[fail(display = "Invalid psk")]
    InvalidPsk,
}

/// The basic handshake patterns.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakePattern {
    // 7.4 One-way handshake patterns
    N,
    K,
    X,

    // 7.5. Interactive handshake patterns (fundamental)
    NN,
    NK,
    NX,
    KN,
    KK,
    KX,
    XN,
    XK,
    XX,
    IN,
    IK,
    IX,
    // 7.6. Interactive handshake patterns (deferred)
    NK1,
    NX1,
    X1N,
    X1K,
    XK1,
    X1K1,
    X1X,
    XX1,
    X1X1,
    K1N,
    K1K,
    KK1,
    K1K1,
    K1X,
    KX1,
    K1X1,
    I1N,
    I1K,
    IK1,
    I1K1,
    I1X,
    IX1,
    I1X1,
}

impl HandshakePattern {
    /// If the protocol is one-way only.
    pub fn is_oneway(&self) -> bool {
        match self {
            N | X | K => true,
            _ => false,
        }
    }

    /// Whether this pattern requires a long-term static key.
    pub fn needs_local_static_key(&self, role: Role) -> bool {
        match role {
            Role::Initiator => match self {
                N | NN | NK | NX => false,
                _ => true,
            },
            Role::Responder => match self {
                NN | XN | KN | IN => false,
                _ => true,
            },
        }
    }

    /// Whether this pattern demands a remote public key pre-message.
    pub fn needs_known_remote_pubkey(&self, role: Role) -> bool {
        match role {
            Role::Initiator => match self {
                N | K | X | NK | XK | KK | IK => true,
                _ => false,
            },
            Role::Responder => match self {
                K | KN | KK | KX => true,
                _ => false,
            },
        }
    }

    /// Returns the tokens of a handshake.
    pub fn tokens(&self) -> HandshakeTokens {
        match self {
            N => tokens::N,
            K => tokens::K,
            X => tokens::X,
            NN => tokens::NN,
            NK => tokens::NK,
            NX => tokens::NX,
            XN => tokens::XN,
            XK => tokens::XK,
            XX => tokens::XX,
            KN => tokens::KN,
            KK => tokens::KK,
            KX => tokens::KX,
            IN => tokens::IN,
            IK => tokens::IK,
            IX => tokens::IX,
            NK1 => tokens::NK1,
            NX1 => tokens::NX1,
            X1N => tokens::X1N,
            X1K => tokens::X1K,
            XK1 => tokens::XK1,
            X1K1 => tokens::X1K1,
            X1X => tokens::X1X,
            XX1 => tokens::XX1,
            X1X1 => tokens::X1X1,
            K1N => tokens::K1N,
            K1K => tokens::K1K,
            KK1 => tokens::KK1,
            K1K1 => tokens::K1K1,
            K1X => tokens::K1X,
            KX1 => tokens::KX1,
            K1X1 => tokens::K1X1,
            I1N => tokens::I1N,
            I1K => tokens::I1K,
            IK1 => tokens::IK1,
            I1K1 => tokens::I1K1,
            I1X => tokens::I1X,
            IX1 => tokens::IX1,
            I1X1 => tokens::I1X1,
        }
    }
}

impl FromStr for HandshakePattern {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "N" => Ok(N),
            "K" => Ok(K),
            "X" => Ok(X),
            "NN" => Ok(NN),
            "NK" => Ok(NK),
            "NX" => Ok(NX),
            "XN" => Ok(XN),
            "XK" => Ok(XK),
            "XX" => Ok(XX),
            "KN" => Ok(KN),
            "KK" => Ok(KK),
            "KX" => Ok(KX),
            "IN" => Ok(IN),
            "IK" => Ok(IK),
            "IX" => Ok(IX),
            "NK1" => Ok(NK1),
            "NX1" => Ok(NX1),
            "X1N" => Ok(X1N),
            "X1K" => Ok(X1K),
            "XK1" => Ok(XK1),
            "X1K1" => Ok(X1K1),
            "X1X" => Ok(X1X),
            "XX1" => Ok(XX1),
            "X1X1" => Ok(X1X1),
            "K1N" => Ok(K1N),
            "K1K" => Ok(K1K),
            "KK1" => Ok(KK1),
            "K1K1" => Ok(K1K1),
            "K1X" => Ok(K1X),
            "KX1" => Ok(KX1),
            "K1X1" => Ok(K1X1),
            "I1N" => Ok(I1N),
            "I1K" => Ok(I1K),
            "IK1" => Ok(IK1),
            "I1K1" => Ok(I1K1),
            "I1X" => Ok(I1X),
            "IX1" => Ok(IX1),
            "I1X1" => Ok(I1X1),
            _ => Err(PatternError::UnsupportedHandshakeType),
        }
    }
}

/// A modifier applied to the base pattern as defined in the Noise spec.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Modifier {
    /// Insert a PSK to mix at the associated position.
    Psk(u8),
    /// Modify the base pattern to its "fallback" form.
    Fallback,
    /// Modify the base pattern to its "sig" form. See the noise signature
    /// extension for more information.
    Sig,
}

impl FromStr for Modifier {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("psk") {
            let n: u8 = s[3..].parse().map_err(|_| PatternError::InvalidPsk)?;
            Ok(Self::Psk(n))
        } else if s == "fallback" {
            Ok(Self::Fallback)
        } else if s == "sig" {
            Ok(Self::Sig)
        } else {
            Err(PatternError::UnsupportedModifier)
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct HandshakeModifiers {
    psks: Vec<u8>,
    fallback: bool,
    sig: bool,
}

impl FromStr for HandshakeModifiers {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(Self::default())
        } else {
            let modifier_names = s.split('+');
            let mut psks = vec![];
            let mut fallback = false;
            let mut sig = false;
            for modifier_name in modifier_names {
                let modifier = modifier_name.parse()?;
                match modifier {
                    Modifier::Psk(n) => psks.push(n),
                    Modifier::Fallback => fallback = true,
                    Modifier::Sig => sig = true,
                }
            }
            Ok(Self {
                psks,
                fallback,
                sig,
            })
        }
    }
}

/// The pattern/modifier combination choice (no primitives specified) for a
/// full noise protocol definition.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Handshake {
    name: String,
    pattern: HandshakePattern,
    modifiers: HandshakeModifiers,
}

impl Handshake {
    /// Returns the name of the handshake.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Parse and split a base HandshakePattern from its optional modifiers.
    fn parse_pattern_and_modifier(s: &str) -> Result<(HandshakePattern, &str), PatternError> {
        for i in (1..=4).rev() {
            if s.len() > i - 1 && s.is_char_boundary(i) {
                if let Ok(p) = s[..i].parse() {
                    return Ok((p, &s[i..]));
                }
            }
        }
        Err(PatternError::UnsupportedHandshakeType)
    }

    /// Returns the base pattern of the handshake.
    pub fn pattern(&self) -> &HandshakePattern {
        &self.pattern
    }

    /// Returns the number of psks used in the handshake.
    pub fn number_of_psks(&self) -> usize {
        self.modifiers.psks.len()
    }

    /// Whether the pattern has a fallback modifier.
    pub fn is_fallback(&self) -> bool {
        self.modifiers.fallback
    }

    /// Wheather the pattern has a sig modifier.
    pub fn is_sig(&self) -> bool {
        self.modifiers.sig
    }

    /// Returns the tokens of a handshake pattern.
    pub fn tokens(&self) -> (&'static [Token], &'static [Token], Vec<Vec<Token>>) {
        let base = self.pattern.tokens();
        let mut handshake: Vec<Vec<Token>> = base.handshake.iter().map(|p| p.to_vec()).collect();
        for n in self.modifiers.psks.iter() {
            if *n == 0 {
                handshake[0 as usize].insert(0, Token::Psk);
            } else {
                handshake[*n as usize - 1].push(Token::Psk);
            }
        }

        if self.modifiers.sig {
            handshake = handshake
                .into_iter()
                .enumerate()
                .map(|(i, tokens)| {
                    let replace = if i % 2 == 1 { Token::ES } else { Token::SE };
                    let forbidden = if i % 2 == 0 { Token::ES } else { Token::SE };
                    tokens
                        .into_iter()
                        .map(|token| {
                            assert!(token != forbidden);
                            if token == replace {
                                Token::Sig
                            } else {
                                token
                            }
                        })
                        .collect()
                })
                .collect();
        }

        (base.initiator, base.responder, handshake)
    }
}

impl FromStr for Handshake {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (pattern, remainder) = Self::parse_pattern_and_modifier(s)?;
        let modifiers = remainder.parse()?;
        let name = s.to_string();
        Ok(Self {
            name,
            pattern,
            modifiers,
        })
    }
}

macro_rules! pattern {
    ($name:ident {
        $initiator:expr,
        $responder:expr,
        ...
        $($handshake:expr,)*
    }) => {
        pattern!($name, stringify!($name), $initiator, $responder, $($handshake,)*);
    };
    ($const_name:ident, $name:expr, $initiator:expr, $responder:expr, $($handshake:expr,)*) => {
        pub const $const_name: HandshakeTokens = HandshakeTokens {
            name: $name,
            initiator: &$initiator,
            responder: &$responder,
            handshake: &[$(&$handshake,)*],
        };
    };
}

mod tokens {
    use super::{HandshakeTokens, Token::*};

    // 7.2 - One-way Patterns
    pattern!(N {
        [],
        [S],
        ...
        [E, ES],
    });

    pattern!(K {
        [S],
        [S],
        ...
        [E, ES, SS],
    });

    pattern!(X {
        [],
        [S],
        ...
        [E, ES, S, SS],
    });

    // 7.3 - Interactive patterns (fundamental)
    pattern!(NN {
        [],
        [],
        ...
        [E],
        [E, EE],
    });

    pattern!(NK {
        [],
        [S],
        ...
        [E, ES],
        [E, EE],
    });

    pattern!(NX {
        [],
        [],
        ...
        [E],
        [E, EE, S, ES],
    });

    pattern!(KN {
        [S],
        [],
        ...
        [E],
        [E, EE, SE],
    });

    pattern!(KK {
        [S],
        [S],
        ...
        [E, ES, SS],
        [E, EE, SE],
    });

    pattern!(KX {
        [S],
        [],
        ...
        [E],
        [E, EE, SE, S, ES],
    });

    pattern!(XN {
        [],
        [],
        ...
        [E],
        [E, EE],
        [S, SE],
    });

    pattern!(XK {
        [],
        [S],
        ...
        [E, ES],
        [E, EE],
        [S, SE],
    });

    pattern!(XX {
        [],
        [],
        ...
        [E],
        [E, EE, S, ES],
        [S, SE],
    });

    pattern!(IN {
        [],
        [],
        ...
        [E, S],
        [E, EE, SE],
    });

    pattern!(IK {
        [],
        [S],
        ...
        [E, ES, S, SS],
        [E, EE, SE],
    });

    pattern!(IX {
        [],
        [],
        ...
        [E, S],
        [E, EE, SE, S, ES],
    });

    pattern!(NK1 {
        [],
        [S],
        ...
        [E],
        [E, EE, ES],
    });

    pattern!(NX1 {
        [],
        [],
        ...
        [E],
        [E, EE, S],
        [ES],
    });

    pattern!(X1N {
        [],
        [],
        ...
        [E],
        [E, EE],
        [S],
        [SE],
    });

    pattern!(X1K {
        [],
        [S],
        ...
        [E, ES],
        [E, EE],
        [S],
        [SE],
    });

    pattern!(XK1 {
        [],
        [S],
        ...
        [E],
        [E, EE, ES],
        [S, SE],
    });

    pattern!(X1K1 {
        [],
        [S],
        ...
        [E],
        [E, EE, ES],
        [S],
        [SE],
    });

    pattern!(X1X {
        [],
        [],
        ...
        [S],
        [E, EE, S, ES],
        [S],
        [SE],
    });

    pattern!(XX1 {
        [],
        [],
        ...
        [E],
        [E, EE, S],
        [ES, S, SE],
    });

    pattern!(X1X1 {
        [],
        [],
        ...
        [E],
        [E, EE, S],
        [ES, S],
        [SE],
    });

    pattern!(K1N {
        [S],
        [],
        ...
        [E],
        [E, EE],
        [SE],
    });

    pattern!(K1K {
        [S],
        [S],
        ...
        [E, ES],
        [E, EE],
        [SE],
    });

    pattern!(KK1 {
        [S],
        [S],
        ...
        [E],
        [E, EE, SE, ES],
    });

    pattern!(K1K1 {
        [S],
        [S],
        ...
        [E],
        [E, EE, ES],
        [SE],
    });

    pattern!(K1X {
        [S],
        [],
        ...
        [E],
        [E, EE, S, ES],
        [SE],
    });

    pattern!(KX1 {
        [S],
        [],
        ...
        [E],
        [E, EE, SE, S],
        [ES],
    });

    pattern!(K1X1 {
        [S],
        [],
        ...
        [E],
        [E, EE, S],
        [SE, ES],
    });

    pattern!(I1N {
        [],
        [],
        ...
        [E, S],
        [E, EE],
        [SE],
    });

    pattern!(I1K {
        [],
        [S],
        ...
        [E, ES, S],
        [E, EE],
        [SE],
    });

    pattern!(IK1 {
        [],
        [S],
        ...
        [E, S],
        [E, EE, SE, ES],
    });

    pattern!(I1K1 {
        [],
        [S],
        ...
        [E, S],
        [E, EE, ES],
        [SE],
    });

    pattern!(I1X {
        [],
        [],
        ...
        [E, S],
        [E, EE, S, ES],
        [SE],
    });

    pattern!(IX1 {
        [],
        [],
        ...
        [E, S],
        [E, EE, SE, E],
        [ES],
    });

    pattern!(I1X1 {
        [],
        [],
        ...
        [E, S],
        [E, EE, S],
        [SE, ES],
    });
}
