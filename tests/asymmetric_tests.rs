extern crate disco_rs;
use disco_rs::asymmetric::{self, KeyPair};

#[test]
fn test_dh_correctness() {
    let kp1 = KeyPair::gen();
    let kp2 = KeyPair::gen();

    let secret1 = asymmetric::dh(&kp1, kp2.pub_key_bytes());
    let secret2 = asymmetric::dh(&kp2, kp1.pub_key_bytes());

    assert_eq!(secret1, secret2);
}
