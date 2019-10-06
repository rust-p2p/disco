use disco_rs::patterns::{NOISE_KK, NOISE_XX};
use disco_rs::x25519::{PublicKey, StaticSecret};
use disco_rs::{ConfigBuilder, PublicKeyVerifier, Role, Session};

#[test]
fn test_kk_session() {
    let secret1 = StaticSecret::new(&mut rand::rngs::OsRng);
    let public1 = PublicKey::from(&secret1);

    let secret2 = StaticSecret::new(&mut rand::rngs::OsRng);
    let public2 = PublicKey::from(&secret2);

    let config1 = ConfigBuilder::new(NOISE_KK, Role::Initiator)
        .secret(secret1)
        .remote_public(public2)
        .build();

    let config2 = ConfigBuilder::new(NOISE_KK, Role::Responder)
        .secret(secret2)
        .remote_public(public1)
        .build();

    let session1 = Session::new(config1);
    let session2 = Session::new(config2);
}

struct Verifier;

impl PublicKeyVerifier for Verifier {
    fn verify(&self, _public: &PublicKey, _proof: &[u8]) -> bool {
        true
    }
}

#[test]
fn test_xx_session() {
    let secret1 = StaticSecret::new(&mut rand::rngs::OsRng);
    let public1 = PublicKey::from(&secret1);

    let secret2 = StaticSecret::new(&mut rand::rngs::OsRng);
    let public2 = PublicKey::from(&secret2);

    let config1 = ConfigBuilder::new(NOISE_XX, Role::Initiator)
        .secret(secret1)
        .public_key_verifier(Verifier)
        .public_key_proof(vec![])
        .build();

    let config2 = ConfigBuilder::new(NOISE_XX, Role::Responder)
        .secret(secret2)
        .public_key_verifier(Verifier)
        .public_key_proof(vec![])
        .build();

    let session1 = Session::new(config1);
    let session2 = Session::new(config2);
}
