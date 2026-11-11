//! The web boundary: converts JS values to Rust and back. The input checks and
//! the cryptography live in veruszsupportcore, shared with the mobile crate.

use js_sys::Uint8Array;
use secrecy::{ExposeSecret, SecretVec};
use wasm_bindgen::prelude::*;

use veruszsupportcore::ZSupportError;

// #[wasm_bindgen(start)]
// pub fn init_panic_hook() {
//     #[cfg(feature = "console_error_panic_hook")]
//     console_error_panic_hook::set_once();
// }

/// Copies sensitive JS bytes (seed, keys, plaintext) into a SecretVec, which is
/// wiped when dropped.
fn secret_bytes(bytes: Uint8Array) -> SecretVec<u8> {
    SecretVec::new(bytes.to_vec())
}

/// JS callers get the error message as a string, as before.
fn to_js_error(error: ZSupportError) -> JsValue {
    JsValue::from_str(&error.to_string())
}

/// Sets a Uint8Array field on a JS Object from a public byte slice.
fn set_bytes(obj: &js_sys::Object, key: &str, bytes: &[u8])-> Result<(), JsValue> {
    js_sys::Reflect::set(
        obj,
        &JsValue::from_str(key),
        &Uint8Array::from(bytes),
    )?;
    Ok(())
}

/// Sets a nullable Uint8Array field on a JS Object.
/// Pass None to set null — used for ptional secret fields.
fn set_bytes_or_null(obj: &js_sys::Object, key: &str, bytes: Option<&[u8]>) -> Result<(), JsValue> {
    let val = match bytes {
        Some(b) => JsValue::from(Uint8Array::from(b)),
        None    => JsValue::NULL,
    };
    js_sys::Reflect::set(obj, &JsValue::from_str(key), &val)?;
    Ok(())
}

// generate channel keys for encryption and decryption

#[wasm_bindgen]
pub fn z_get_encryptionaddress(
    seed: Option<Uint8Array>,
    spending_key: Option<Uint8Array>,
    hd_index: Option<u32>,
    encryption_index: Option<u32>,
    from_id: Option<Uint8Array>,
    to_id: Option<Uint8Array>,
    return_secret: bool,
) -> Result<JsValue, JsValue> {

    let from_id = from_id.map(|u| u.to_vec());
    let to_id = to_id.map(|u| u.to_vec());

    let keys = veruszsupportcore::z_get_encryptionaddress(
        seed.map(secret_bytes),
        spending_key.map(secret_bytes),
        hd_index,
        encryption_index,
        from_id.as_deref(),
        to_id.as_deref(),
        return_secret,
    ).map_err(to_js_error)?;

    let obj = js_sys::Object::new();
    set_bytes(         &obj, "address",     keys.address.to_bytes().as_ref())?;
    set_bytes(         &obj, "ivk",         keys.ivk_bytes.expose_secret())?;
    set_bytes(         &obj, "extfvk",         keys.extfvk_bytes.expose_secret())?;
    set_bytes_or_null( &obj, "spendingKey",
        keys.spending_key_bytes.as_ref().map(|sk| sk.expose_secret().as_ref()))?;

    Ok(obj.into())
}

// encrypt data buffer

#[wasm_bindgen]
pub fn encrypt_v_data(
    address: Uint8Array,
    data: Uint8Array,
    return_ssk: bool,
) -> Result<JsValue, JsValue> {

    let payload = veruszsupportcore::encrypt_v_data(
        &address.to_vec(),
        secret_bytes(data),
        return_ssk,
    ).map_err(to_js_error)?;

    let obj = js_sys::Object::new();
    set_bytes(         &obj, "ephemeralPublicKey", &payload.ephemeral_public_key)?;
    set_bytes(         &obj, "encryptedData",          &payload.encrypted_data)?;
    set_bytes_or_null( &obj, "symmetricKey",
        payload.symmetric_key.as_ref().map(|sk| sk.expose_secret().as_ref()))?;

    Ok(obj.into())
}

// decrypt_data 

#[wasm_bindgen]
pub fn decrypt_v_data(
    ivk: Option<Uint8Array>,
    epk: Option<Uint8Array>,
    datatodecrypt: Uint8Array,
    ssk: Option<Uint8Array>,
) -> Result<Uint8Array, JsValue> {

    let epk = epk.map(|u| u.to_vec());

    let decrypted = veruszsupportcore::decrypt_v_data(
        ivk.map(secret_bytes),
        epk.as_deref(),
        secret_bytes(datatodecrypt),
        ssk.map(secret_bytes),
    ).map_err(to_js_error)?;

    Ok(Uint8Array::from(decrypted.expose_secret().as_slice()))
}
