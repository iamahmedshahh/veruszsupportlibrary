//! veruszsupportweb: the exports the web engine (src/engine.ts) calls. They
//! take and return JS values, so these tests run inside Node, as WebAssembly:
//! wasm-pack test --node veruszsupporttests.

#![cfg(target_arch = "wasm32")]

use js_sys::{Array, Error, Reflect, Uint8Array};
use veruszsupport::{decrypt_data, encrypt_data, fresh_salt, limits, z_get_encryption_address};
use veruszsupportcore::limits::LIMITS;
use veruszsupporttests::{
    from_hex, to_hex, ADDRESS, DECRYPTION_FAILED, FROM_ID, HD_INDEX_REFUSED, IVK, SEED, TO_ID,
    WRAPPING_INDICES,
};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

fn js_bytes(bytes: &[u8]) -> Uint8Array {
    Uint8Array::from(bytes)
}

/// A field of an object Rust returned.
fn field(object: &JsValue, name: &str) -> JsValue {
    Reflect::get(object, &JsValue::from_str(name)).expect("an object")
}

/// A Uint8Array field, as bytes.
fn bytes(object: &JsValue, name: &str) -> Vec<u8> {
    field(object, name)
        .dyn_into::<Uint8Array>()
        .expect("a Uint8Array")
        .to_vec()
}

/// The name and message of the JS Error Rust threw (to_js_error).
fn error(thrown: JsValue) -> (String, String) {
    let error: Error = thrown.dyn_into().expect("a JS Error");
    (error.name().into(), error.message().into())
}

/// Keys from SEED for the two IDs, with indices as JavaScript numbers.
fn derive(hd_index: Option<f64>, return_secret: bool) -> Result<JsValue, JsValue> {
    z_get_encryption_address(
        Some(js_bytes(&SEED)),
        None,
        hd_index,
        Some(0.0),
        Some(js_bytes(&from_hex(FROM_ID))),
        Some(js_bytes(&from_hex(TO_ID))),
        return_secret,
    )
}

#[wasm_bindgen_test]
fn derives_the_known_vector() {
    let keys = derive(Some(0.0), false).unwrap();

    assert_eq!(to_hex(&bytes(&keys, "address")), ADDRESS);
    assert_eq!(to_hex(&bytes(&keys, "ivk")), IVK);
    assert_eq!(bytes(&keys, "extfvk").len(), 169);
    assert!(field(&keys, "spendingKey").is_undefined());
}

#[wasm_bindgen_test]
fn returns_the_spending_key_only_when_asked() {
    let keys = derive(None, true).unwrap();

    assert_eq!(bytes(&keys, "spendingKey").len(), 169);
}

#[wasm_bindgen_test]
fn refuses_indices_that_a_u32_would_wrap() {
    for index in WRAPPING_INDICES {
        let thrown = derive(Some(index), false).expect_err("refused");

        assert_eq!(
            error(thrown),
            ("InvalidInput".into(), HD_INDEX_REFUSED.into()),
            "{index} was taken"
        );
    }
}

#[wasm_bindgen_test]
fn throws_errors_named_after_their_kind_with_the_core_message() {
    let thrown = z_get_encryption_address(
        Some(js_bytes(&[7; 31])),
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .expect_err("refused");

    assert_eq!(
        error(thrown),
        ("InvalidInput".into(), "seed must be 32 or 64 bytes".into())
    );
}

#[wasm_bindgen_test]
fn encrypts_and_decrypts_with_the_ivk_and_with_the_ssk() {
    let keys = derive(None, false).unwrap();
    let payload =
        encrypt_data(js_bytes(&bytes(&keys, "address")), js_bytes(b"hello"), true).unwrap();
    let encrypted = bytes(&payload, "encryptedData");

    let with_ivk = decrypt_data(
        Some(js_bytes(&bytes(&keys, "ivk"))),
        Some(js_bytes(&bytes(&payload, "ephemeralPublicKey"))),
        js_bytes(&encrypted),
        None,
    )
    .unwrap();
    let with_ssk = decrypt_data(
        None,
        None,
        js_bytes(&encrypted),
        Some(js_bytes(&bytes(&payload, "symmetricKey"))),
    )
    .unwrap();

    assert_eq!(with_ivk.to_vec(), b"hello");
    assert_eq!(with_ssk.to_vec(), b"hello");
}

#[wasm_bindgen_test]
fn returns_the_ssk_only_when_asked() {
    let keys = derive(None, false).unwrap();

    let payload = encrypt_data(
        js_bytes(&bytes(&keys, "address")),
        js_bytes(b"hello"),
        false,
    )
    .unwrap();

    assert!(field(&payload, "symmetricKey").is_undefined());
}

#[wasm_bindgen_test]
fn a_changed_ciphertext_is_a_crypto_error() {
    let keys = derive(None, false).unwrap();
    let payload = encrypt_data(
        js_bytes(&bytes(&keys, "address")),
        js_bytes(b"hello"),
        false,
    )
    .unwrap();
    let mut changed = bytes(&payload, "encryptedData");
    changed[0] ^= 1;

    let thrown = decrypt_data(
        Some(js_bytes(&bytes(&keys, "ivk"))),
        Some(js_bytes(&bytes(&payload, "ephemeralPublicKey"))),
        js_bytes(&changed),
        None,
    )
    .expect_err("refused");

    assert_eq!(error(thrown), ("Crypto".into(), DECRYPTION_FAILED.into()));
}

#[wasm_bindgen_test]
fn fresh_salts_are_salt_sized_and_differ() {
    let first = fresh_salt().unwrap().to_vec();
    let second = fresh_salt().unwrap().to_vec();

    assert_eq!(first.len(), LIMITS.salt_bytes as usize);
    assert_ne!(first, second);
}

#[wasm_bindgen_test]
fn limits_are_the_cores() {
    let limits = limits().unwrap();
    let number = |name: &str| field(&limits, name).as_f64().expect("a number") as u32;
    let seed_lengths: Vec<u32> = Array::from(&field(&limits, "seedLengths"))
        .iter()
        .map(|length| length.as_f64().expect("a number") as u32)
        .collect();

    assert_eq!(number("maxIndex"), LIMITS.max_index);
    assert_eq!(seed_lengths, LIMITS.seed_lengths.to_vec());
    assert_eq!(number("spendingKeyBytes"), LIMITS.spending_key_bytes);
    assert_eq!(number("paymentAddressBytes"), LIMITS.payment_address_bytes);
    assert_eq!(number("identityIdBytes"), LIMITS.identity_id_bytes);
    assert_eq!(number("ivkBytes"), LIMITS.ivk_bytes);
    assert_eq!(number("epkBytes"), LIMITS.epk_bytes);
    assert_eq!(number("sskBytes"), LIMITS.ssk_bytes);
    assert_eq!(number("tagBytes"), LIMITS.tag_bytes);
    assert_eq!(number("maxPayloadBytes"), LIMITS.max_payload_bytes);
    assert_eq!(number("saltBytes"), LIMITS.salt_bytes);
}
