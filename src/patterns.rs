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
    // TODO
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
            _ => Err(PatternError::UnsupportedHandshakeType),
        }
    }
}

/// A modifier applied to the base pattern as defined in the Noise spec.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum HandshakeModifier {
    /// Insert a PSK to mix at the associated position.
    Psk(u8),
    /// Modify the base pattern to its "fallback" form.
    Fallback,
}

impl FromStr for HandshakeModifier {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("psk") {
            let n: u8 = s[3..].parse().map_err(|_| PatternError::InvalidPsk)?;
            Ok(Self::Psk(n))
        } else if s == "fallback" {
            Ok(Self::Fallback)
        } else {
            Err(PatternError::UnsupportedModifier)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HandshakeModifierList(Vec<HandshakeModifier>);

impl FromStr for HandshakeModifierList {
    type Err = PatternError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(Self(vec![]))
        } else {
            let modifier_names = s.split('+');
            let mut modifiers = vec![];
            for modifier_name in modifier_names {
                modifiers.push(modifier_name.parse()?);
            }
            Ok(Self(modifiers))
        }
    }
}

/// The pattern/modifier combination choice (no primitives specified) for a
/// full noise protocol definition.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Handshake {
    name: String,
    pattern: HandshakePattern,
    modifiers: HandshakeModifierList,
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
        self.modifiers
            .0
            .iter()
            .filter(|modifier| {
                if let HandshakeModifier::Psk(_) = modifier {
                    return true;
                }
                false
            })
            .count()
    }

    /// Returns the tokens of a handshake pattern.
    pub fn tokens(&self) -> (&'static [Token], &'static [Token], Vec<Vec<Token>>) {
        let base = self.pattern.tokens();
        let mut handshake: Vec<Vec<Token>> = base.handshake.iter().map(|p| p.to_vec()).collect();
        for modifier in self.modifiers.0.iter() {
            if let HandshakeModifier::Psk(n) = modifier {
                if *n == 0 {
                    handshake[0 as usize].insert(0, Token::Psk);
                } else {
                    handshake[*n as usize - 1].push(Token::Psk);
                }
            }
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
}
