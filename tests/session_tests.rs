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

    let mut session1 = Session::new(config1);
    let mut session2 = Session::new(config2);

    println!("->");
    let ct = session1.write_message(b"e es ss".to_vec()).expect("ct");
    let pt = session2.read_message(ct).expect("pt");
    assert_eq!(&pt, b"e es ss");

    println!("<-");
    let ct = session2.write_message(b"e ee se".to_vec()).expect("ct");
    let pt = session1.read_message(ct).expect("pt");
    assert_eq!(&pt, b"e ee se");

    println!("->");
    let ct = session1.write_message(b"hello".to_vec()).expect("ct");
    let pt = session2.read_message(ct).expect("pt");
    assert_eq!(&pt, b"hello");
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
    //let public1 = PublicKey::from(&secret1);

    let secret2 = StaticSecret::new(&mut rand::rngs::OsRng);
    //let public2 = PublicKey::from(&secret2);

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

    let mut session1 = Session::new(config1);
    let mut session2 = Session::new(config2);

    println!("->");
    let ct = session1.write_message(b"e".to_vec()).expect("ct");
    let pt = session2.read_message(ct).expect("pt");
    assert_eq!(&pt, b"e");

    println!("<-");
    let ct = session2.write_message(b"e ee s es".to_vec()).expect("ct");
    let pt = session1.read_message(ct).expect("pt");
    assert_eq!(&pt, b"e ee s es");

    println!("->");
    let ct = session1.write_message(b"s se".to_vec()).expect("ct");
    let pt = session2.read_message(ct).expect("pt");
    assert_eq!(&pt, b"s se");

    println!("<-");
    let ct = session2.write_message(b"hello".to_vec()).expect("ct");
    let pt = session1.read_message(ct).expect("pt");
    assert_eq!(&pt, b"hello");
}
