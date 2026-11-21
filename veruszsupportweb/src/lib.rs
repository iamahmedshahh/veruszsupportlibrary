//! The web boundary: converts JS values to Rust and back. The input checks and
//! the cryptography live in veruszsupportcore, shared with the mobile crate.
//! Apps call these through veruszsupportlib (src/engine.ts), never directly.

use js_sys::{Array, Object, Reflect, Uint8Array};
use secrecy::{ExposeSecret, SecretVec};
use wasm_bindgen::prelude::*;

use veruszsupportcore::limits::LIMITS;
use veruszsupportcore::VerusZSupportError;

/// Copies sensitive JS bytes (seed, keys, plaintext) into a SecretVec, which is
/// wiped when dropped.
fn secret_bytes(bytes: Uint8Array) -> SecretVec<u8> {
    SecretVec::new(bytes.to_vec())
}

/// Throws the error as a JS Error named after its kind ("InvalidInput" or
/// "Crypto"). The TypeScript wrapper turns it into a VerusZSupportError, the
/// same class the mobile package throws.
fn to_js_error(error: VerusZSupportError) -> JsValue {
    let js_error = js_sys::Error::new(error.message());
    js_error.set_name(error.kind());
    js_error.into()
}

/// Sets a field on a JS Object.
fn set(obj: &Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    Reflect::set(obj, &JsValue::from_str(key), value)?;
    Ok(())
}

/// Sets a Uint8Array field on a JS Object from a byte slice.
fn set_bytes(obj: &Object, key: &str, bytes: &[u8]) -> Result<(), JsValue> {
    set(obj, key, &Uint8Array::from(bytes))
}

/// Sets an optional Uint8Array field: undefined when absent, as in the mobile
/// package.
fn set_optional_bytes(obj: &Object, key: &str, bytes: Option<&[u8]>) -> Result<(), JsValue> {
    match bytes {
        Some(bytes) => set_bytes(obj, key, bytes),
        None => set(obj, key, &JsValue::UNDEFINED),
    }
}

/// The sizes and ranges the library checks, from veruszsupportcore's limits.
#[wasm_bindgen]
pub fn limits() -> Result<JsValue, JsValue> {
    let seed_lengths: Array = LIMITS
        .seed_lengths
        .iter()
        .map(|&length| JsValue::from(length))
        .collect();

    let obj = Object::new();
    set(&obj, "maxIndex", &LIMITS.max_index.into())?;
    set(&obj, "seedLengths", &seed_lengths)?;
    set(&obj, "spendingKeyBytes", &LIMITS.spending_key_bytes.into())?;
    set(
        &obj,
        "paymentAddressBytes",
        &LIMITS.payment_address_bytes.into(),
    )?;
    set(&obj, "identityIdBytes", &LIMITS.identity_id_bytes.into())?;
    set(&obj, "ivkBytes", &LIMITS.ivk_bytes.into())?;
    set(&obj, "epkBytes", &LIMITS.epk_bytes.into())?;
    set(&obj, "sskBytes", &LIMITS.ssk_bytes.into())?;
    set(&obj, "tagBytes", &LIMITS.tag_bytes.into())?;
    set(&obj, "maxPayloadBytes", &LIMITS.max_payload_bytes.into())?;
    set(&obj, "saltBytes", &LIMITS.salt_bytes.into())?;

    Ok(obj.into())
}

/// A fresh DataDescriptor salt, from crypto.getRandomValues.
#[wasm_bindgen]
pub fn fresh_salt() -> Result<Uint8Array, JsValue> {
    let salt = veruszsupportcore::fresh_salt().map_err(to_js_error)?;
    Ok(Uint8Array::from(salt.as_slice()))
}

/// Derives the Sapling channel keys used for encryption and decryption.
///
/// The indices are JS numbers, checked in veruszsupportcore before use.
#[wasm_bindgen]
pub fn z_get_encryption_address(
    seed: Option<Uint8Array>,
    spending_key: Option<Uint8Array>,
    hd_index: Option<f64>,
    encryption_index: Option<f64>,
    from_id: Option<Uint8Array>,
    to_id: Option<Uint8Array>,
    return_secret: bool,
) -> Result<JsValue, JsValue> {
    let hd_index = veruszsupportcore::index_from_js(hd_index, "hdIndex").map_err(to_js_error)?;
    let encryption_index = veruszsupportcore::index_from_js(encryption_index, "encryptionIndex")
        .map_err(to_js_error)?;
    let from_id = from_id.map(|bytes| bytes.to_vec());
    let to_id = to_id.map(|bytes| bytes.to_vec());

    let keys = veruszsupportcore::z_get_encryption_address(
        seed.map(secret_bytes),
        spending_key.map(secret_bytes),
        hd_index,
        encryption_index,
        from_id.as_deref(),
        to_id.as_deref(),
        return_secret,
    )
    .map_err(to_js_error)?;

    let obj = Object::new();
    set_bytes(&obj, "address", &keys.address.to_bytes())?;
    set_bytes(&obj, "ivk", keys.ivk_bytes.expose_secret())?;
    set_bytes(&obj, "extfvk", keys.extfvk_bytes.expose_secret())?;
    set_optional_bytes(
        &obj,
        "spendingKey",
        keys.spending_key_bytes
            .as_ref()
            .map(|sk| sk.expose_secret().as_slice()),
    )?;

    Ok(obj.into())
}

/// Encrypts `data` to a Sapling payment address.
#[wasm_bindgen]
pub fn encrypt_data(
    address: Uint8Array,
    data: Uint8Array,
    return_ssk: bool,
) -> Result<JsValue, JsValue> {
    let payload =
        veruszsupportcore::encrypt_data(&address.to_vec(), secret_bytes(data), return_ssk)
            .map_err(to_js_error)?;

    let obj = Object::new();
    set_bytes(&obj, "ephemeralPublicKey", &payload.ephemeral_public_key)?;
    set_bytes(&obj, "encryptedData", &payload.encrypted_data)?;
    set_optional_bytes(
        &obj,
        "symmetricKey",
        payload
            .symmetric_key
            .as_ref()
            .map(|ssk| ssk.expose_secret().as_slice()),
    )?;

    Ok(obj.into())
}

/// Decrypts `encrypted_data` with exactly one key: `ivk` (with `epk`) or `ssk`.
#[wasm_bindgen]
pub fn decrypt_data(
    ivk: Option<Uint8Array>,
    epk: Option<Uint8Array>,
    encrypted_data: Uint8Array,
    ssk: Option<Uint8Array>,
) -> Result<Uint8Array, JsValue> {
    let epk = epk.map(|bytes| bytes.to_vec());

    let decrypted = veruszsupportcore::decrypt_data(
        ivk.map(secret_bytes),
        epk.as_deref(),
        secret_bytes(encrypted_data),
        ssk.map(secret_bytes),
    )
    .map_err(to_js_error)?;

    Ok(Uint8Array::from(decrypted.expose_secret().as_slice()))
}
