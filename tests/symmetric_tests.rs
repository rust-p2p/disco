// Most tests in this file were translated from symmetric_tests.go in StrobeGo

use disco::symmetric::{self, AuthCiphertext, AuthPlaintext, DiscoHash};

#[test]
fn test_known_hash() {
    let input = b"hi, how are you?";
    let hash = symmetric::hash(input, 32);
    let expected_hash = [
        0xed, 0xa8, 0x50, 0x6c, 0x1f, 0xb0, 0xbb, 0xcc, 0x3f, 0x62, 0x62, 0x6f, 0xef, 0x07, 0x4b,
        0xbf, 0x2d, 0x09, 0xa8, 0xc7, 0xc6, 0x08, 0xf3, 0xfa, 0x14, 0x82, 0xc9, 0xa6, 0x25, 0xd0,
        0x0f, 0x75,
    ];

    assert_eq!(hash, &expected_hash[..]);
}

#[test]
fn test_known_derive_keys() {
    let input = b"hi, how are you?";
    let key = symmetric::derive_keys(input, 64);
    let expected_key = [
        0xd6, 0x35, 0x0b, 0xb9, 0xb8, 0x38, 0x84, 0x77, 0x4f, 0xb9, 0xb0, 0x88, 0x16, 0x80, 0xfc,
        0x65, 0x6b, 0xe1, 0x07, 0x1f, 0xff, 0x75, 0xd3, 0xfa, 0x94, 0x51, 0x9d, 0x50, 0xa1, 0x0b,
        0x92, 0x64, 0x4e, 0x3c, 0xc1, 0xca, 0xe1, 0x66, 0xa6, 0x01, 0x67, 0xd7, 0xbf, 0x00, 0x13,
        0x70, 0x18, 0x34, 0x5b, 0xb8, 0x05, 0x7b, 0xe4, 0xb0, 0x9f, 0x93, 0x7b, 0x0e, 0x12, 0x06,
        0x6d, 0x5d, 0xc3, 0xdf,
    ];

    assert_eq!(key, &expected_key[..]);
}

#[test]
fn test_streaming_sum() {
    let msg1 = b"hello";
    let msg2 = b"how are you good sir?";
    let msg3 = b"sure thing";
    let msg1c2 = [msg1.to_vec(), msg2.to_vec()].concat();

    // Try with DiscoHash with and without streaming
    let mut h1 = DiscoHash::new(32);
    h1.write(msg1);
    h1.write(msg2);
    let out1 = h1.clone().sum();

    let mut h2 = DiscoHash::new(32);
    h2.write(&msg1c2);
    let out2 = h2.clone().sum();

    assert_eq!(out1, out2);

    // Try streaming more
    h1.write(msg3);
    let out1 = h1.sum();
    h2.write(msg3);
    let out2 = h2.sum();

    assert_eq!(out1, out2);

    // Now check that this agrees with symmetric::hash
    let out3 = symmetric::hash(&[msg1c2, msg3.to_vec()].concat(), 32);
    assert_eq!(out1, out3);
}

#[test]
fn test_nonce_size() {
    let key = vec![
        0xed, 0xa8, 0x50, 0x6c, 0x1f, 0xb0, 0xbb, 0xcc, 0x3f, 0x62, 0x62, 0x6f, 0xef, 0x07, 0x4b,
        0xbf, 0x2d, 0x09, 0xa8, 0xc7, 0xc6, 0x08, 0xf3, 0xfa, 0x14, 0x82, 0xc9, 0xa6, 0x25, 0xd0,
        0x0f, 0x75,
    ];
    let plaintext = b"hello, how are you?".to_vec();
    let ciphertext = symmetric::encrypt(&key, plaintext);

    assert_eq!(ciphertext.into_bytes().len(), 19 + 16 + 24);
}

#[test]
fn test_integrity_correctness() {
    let key = vec![
        0xed, 0xa8, 0x50, 0x6c, 0x1f, 0xb0, 0xbb, 0xcc, 0x3f, 0x62, 0x62, 0x6f, 0xef, 0x07, 0x4b,
        0xbf, 0x2d, 0x09, 0xa8, 0xc7, 0xc6, 0x08, 0xf3, 0xfa, 0x14, 0x82, 0xc9, 0xa6, 0x25, 0xd0,
        0x0f, 0x75,
    ];
    let msg = b"hoy, how are you?".to_vec();
    let boxed_pt = symmetric::protect_integrity(&key, msg.clone());
    let unboxed_pt = symmetric::verify_integrity(&key, boxed_pt).expect("verify_integrity failed");

    assert_eq!(unboxed_pt, msg);
}

#[test]
fn test_encryption_correctness() {
    let key = vec![
        0xed, 0xa8, 0x50, 0x6c, 0x1f, 0xb0, 0xbb, 0xcc, 0x3f, 0x62, 0x62, 0x6f, 0xef, 0x07, 0x4b,
        0xbf, 0x2d, 0x09, 0xa8, 0xc7, 0xc6, 0x08, 0xf3, 0xfa, 0x14, 0x82, 0xc9, 0xa6, 0x25, 0xd0,
        0x0f, 0x75,
    ];
    let plaintexts = [
        &b""[..],
        &b"a"[..],
        &b"ab"[..],
        &b"abc"[..],
        &b"abcd"[..],
        &b"short"[..],
        &b"hello, how are you?"[..],
        &b"this is very short"[..],
        &b"this is very long though, like, very very long, should we test very very long\
           things here?"[..],
    ];

    for pt in plaintexts.into_iter().map(|s| s.to_vec()) {
        let auth_ct = symmetric::encrypt(&key, pt.clone());
        let decrypted = symmetric::decrypt(&key, auth_ct).expect("decrypt auth failed");
        assert_eq!(decrypted, pt);
    }
}

// Make sure from_bytes and into_bytes are inverses of each other
#[test]
fn test_serialization_correctness() {
    let bytes = [[1u8; 8], [2u8; 8], [3u8; 8], [4u8; 8], [5u8; 8], [6u8; 8]].concat();

    assert_eq!(
        AuthPlaintext::from_bytes(bytes.clone())
            .unwrap()
            .into_bytes(),
        bytes
    );
    assert_eq!(
        AuthCiphertext::from_bytes(bytes.clone())
            .unwrap()
            .into_bytes(),
        bytes
    );
}
