use disco_rs::patterns::{NOISE_KK, NOISE_NN, NOISE_NNPSK2, NOISE_XX};
use disco_rs::x25519::{PublicKey, StaticSecret};
use disco_rs::SessionBuilder;
use ed25519_dalek as ed25519;

#[test]
fn test_nn_session() {
    let mut session1 = SessionBuilder::new(NOISE_NN).build_initiator();
    let mut session2 = SessionBuilder::new(NOISE_NN).build_responder();

    println!("-> e");
    let ct = session1.write_message(&[]);
    session2.read_message(&ct).unwrap();

    println!("<- e ee");
    let ct = session2.write_message(&[]);
    session1.read_message(&ct).unwrap();

    let mut session1 = session1.into_transport_mode();
    let mut session2 = session2.into_transport_mode();

    println!("->");
    let ct = session1.write_message(b"hello");
    let pt = session2.read_message(&ct).unwrap();
    assert_eq!(&pt, b"hello");
}

#[test]
fn test_kk_session() {
    let secret1 = StaticSecret::new(&mut rand::rngs::OsRng);
    let public1 = PublicKey::from(&secret1);

    let secret2 = StaticSecret::new(&mut rand::rngs::OsRng);
    let public2 = PublicKey::from(&secret2);

    let mut session1 = SessionBuilder::new(NOISE_KK)
        .secret(secret1)
        .remote_public(public2)
        .build_initiator();

    let mut session2 = SessionBuilder::new(NOISE_KK)
        .secret(secret2)
        .remote_public(public1)
        .build_responder();

    println!("->");
    let ct = session1.write_message(b"e es ss");
    let pt = session2.read_message(&ct).expect("pt");
    assert_eq!(&pt, b"e es ss");

    println!("<-");
    let ct = session2.write_message(b"e ee se");
    let pt = session1.read_message(&ct).expect("pt");
    assert_eq!(&pt, b"e ee se");

    let mut session1 = session1.into_transport_mode();
    let mut session2 = session2.into_transport_mode();

    println!("->");
    let ct = session1.write_message(b"hello");
    let pt = session2.read_message(&ct).expect("pt");
    assert_eq!(&pt, b"hello");
}

#[derive(Clone, Debug)]
struct Verifier {
    root_public: ed25519::PublicKey,
}

impl Verifier {
    pub fn new(root_public: ed25519::PublicKey) -> Self {
        Self { root_public }
    }

    pub fn verify(&self, public: &PublicKey, proof: &[u8]) -> bool {
        if let Ok(sig) = ed25519::Signature::from_bytes(proof) {
            if let Ok(()) = self.root_public.verify(public.as_bytes(), &sig) {
                return true;
            }
        }
        false
    }
}

#[test]
fn test_xx_session() {
    let root = ed25519::Keypair::generate(&mut rand::rngs::OsRng);
    let verifier = Verifier::new(root.public.clone());

    let secret1 = StaticSecret::new(&mut rand::rngs::OsRng);
    let public1 = PublicKey::from(&secret1);
    let proof1 = root.sign(public1.as_bytes());

    let secret2 = StaticSecret::new(&mut rand::rngs::OsRng);
    let public2 = PublicKey::from(&secret2);
    let proof2 = root.sign(public2.as_bytes());

    let mut session1 = SessionBuilder::new(NOISE_XX)
        .secret(secret1)
        .build_initiator();

    let mut session2 = SessionBuilder::new(NOISE_XX)
        .secret(secret2)
        .build_responder();

    println!("-> e");
    let ct = session1.write_message(&[]);
    session2.read_message(&ct).expect("pt");

    println!("<- e ee s es");
    let ct = session2.write_message(&proof2.to_bytes()[..]);
    let proof2 = session1.read_message(&ct).expect("pt");
    let public2 = session1.get_remote_static().expect("s");
    assert!(verifier.verify(public2, &proof2));

    println!("-> s se");
    let ct = session1.write_message(&proof1.to_bytes()[..]);
    let proof1 = session2.read_message(&ct).expect("pt");
    let public1 = session2.get_remote_static().expect("s");
    assert!(verifier.verify(public1, &proof1));

    let mut session1 = session1.into_transport_mode();
    let mut session2 = session2.into_transport_mode();

    println!("<-");
    let ct = session2.write_message(b"hello");
    let pt = session1.read_message(&ct).expect("pt");
    assert_eq!(&pt, b"hello");
}

#[test]
fn test_nnpsk2_session() {
    // Also test prologue and rekeying.
    let mut session1 = SessionBuilder::new(NOISE_NNPSK2)
        .prologue(b"prologue".to_vec())
        .preshared_secret([0u8; 32])
        .build_initiator();

    let mut session2 = SessionBuilder::new(NOISE_NNPSK2)
        .prologue(b"prologue".to_vec())
        .preshared_secret([0u8; 32])
        .build_responder();

    println!("->");
    let ct = session1.write_message(b"e");
    let pt = session2.read_message(&ct).expect("pt");
    assert_eq!(&pt, b"e");

    println!("<-");
    let ct = session2.write_message(b"e ee psk");
    let pt = session1.read_message(&ct).expect("pt");
    assert_eq!(&pt, b"e ee psk");

    let mut session1 = session1.into_transport_mode();
    let mut session2 = session2.into_transport_mode();

    session1.rekey_outgoing();
    session2.rekey_incoming();

    println!("->");
    let ct = session1.write_message(b"hello");
    let pt = session2.read_message(&ct).expect("pt");
    assert_eq!(&pt, b"hello");
}
