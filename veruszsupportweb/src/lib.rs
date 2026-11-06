use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
use secrecy::{ExposeSecret, Secret, SecretVec};

use sapling_crypto::PaymentAddress;

use verus_zfunc::{
    z_getencryptionaddress,
    encrypt_data,
    decrypt_data,
};

/// Upper bound on plaintext crossing the boundary. Policy value — tune to your largest real payload.
const MAX_PAYLOAD_BYTES: u32 = 1024 * 1024; // 1 MiB
/// ChaCha20Poly1305 tag length added to every ciphertext.
const AEAD_TAG_BYTES: u32 = 16;
/// ZIP-32 hardened indices must be < 2^31; the core's ChildIndex::hardened asserts this (panic → trap).
const HARDENED_LIMIT: u32 = 1 << 31;


// #[wasm_bindgen(start)]
// pub fn init_panic_hook() {
//     #[cfg(feature = "console_error_panic_hook")]
//     console_error_panic_hook::set_once();
// }

/// Convert a Uint8Array to a fixed-size Secret<[u8; N]>.
/// Used for ALL sensitive key material (ivk, extfvk, spending key, ssk, seed).

macro_rules! secret_array {
    ($u:expr, $n:expr, $label:literal) => {{
        // check length first: copy_to panics on mismatch
        if $u.length() as usize != $n {
            return Err(JsValue::from_str(concat!(
                "INVALID_LENGTH: ", $label, " must be exactly ", stringify!($n), " bytes"
            )));
        }
        // copy JS bytes directly into the fixed array — no intermediate Vec
        // left unzeroized in WASM linear memory
        let mut arr = [0u8; $n];
        $u.copy_to(&mut arr);
        Secret::new(arr)
    }};
}

/// Converts a Uint8Array to a fixed-size [u8; N].
/// used  only for non-sensitive public bytes (epk, hash160 IDs, address bytes).
macro_rules! pub_array {
   ($u:expr, $n:expr, $label:literal) => {{
        if $u.length() as usize != $n {
            return Err(JsValue::from_str(concat!(
                "INVALID_LENGTH: ", $label, " must be exactly ", stringify!($n), " bytes"
            )));
        }
        let mut arr = [0u8; $n];
        $u.copy_to(&mut arr);
        arr
    }};
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

// seed and spendingKey are alternative key sources — reject ambiguity
    if seed.is_some() && spending_key.is_some() {
        return Err(JsValue::from_str("Provide either seed or spendingKey, not both"));
    }
    // the core's hardened derivation asserts index < 2^31 — reject before it can trap
    if hd_index.map_or(false, |i| i >= HARDENED_LIMIT) {
        return Err(JsValue::from_str("hdIndex must be less than 2^31"));
    }
    if encryption_index.map_or(false, |i| i >= HARDENED_LIMIT) {
        return Err(JsValue::from_str("encryptionIndex must be less than 2^31"));
    }

    let seed = seed.map(|u| SecretVec::new(u.to_vec()));

    let spending_key: Option<Secret<[u8; 169]>> = spending_key
        .map(|u| -> Result<_, JsValue> {
            Ok(secret_array!(u, 169, "spending_key"))
        })
        .transpose()?;

    let from_id: Option<[u8; 20]> = from_id
        .map(|u| -> Result<_, JsValue> {
            Ok(pub_array!(u, 20, "from_id"))
        })
        .transpose()?;

    let to_id: Option<[u8; 20]> = to_id
        .map(|u| -> Result<_, JsValue> {
            Ok(pub_array!(u, 20, "to_id"))
        })
        .transpose()?;

    let keys = z_getencryptionaddress(
        seed.as_ref(),
        spending_key.as_ref(),
        hd_index,
        encryption_index,
        from_id.as_ref(),
        to_id.as_ref(),
        return_secret,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;

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

    let addr_bytes = pub_array!(address, 43, "address");
    let payment_address = PaymentAddress::from_bytes(&addr_bytes)
        .ok_or_else(|| JsValue::from_str("Invalid PaymentAddress bytes"))?;

    if data.length() > MAX_PAYLOAD_BYTES {
        return Err(JsValue::from_str("data exceeds maximum payload size"));
    }
    let plaintext = SecretVec::new(data.to_vec());

    let payload = encrypt_data(&payment_address, &plaintext, return_ssk)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

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

    // exactly one key: ivk (with epk) or ssk — never silently prefer one
    if ivk.is_some() && ssk.is_some() {
        return Err(JsValue::from_str("Provide either ivk (with epk) or ssk, not both"));
    }
    // epk is only meaningful with ivk; drop it in ssk mode
    let epk = if ssk.is_some() { None } else { epk };

    if datatodecrypt.length() > MAX_PAYLOAD_BYTES + AEAD_TAG_BYTES {
        return Err(JsValue::from_str("datatodecrypt exceeds maximum payload size"));
    }

    let ivk: Option<Secret<[u8; 32]>> = ivk
        .map(|u| -> Result<_, JsValue> {
            Ok(secret_array!(u, 32, "ivk"))
        })
        .transpose()?;

    let epk: Option<[u8; 32]> = epk
        .map(|u| -> Result<_, JsValue> {
            Ok(pub_array!(u, 32, "epk"))
        })
        .transpose()?;

    let ssk: Option<Secret<[u8; 32]>> = ssk
        .map(|u| -> Result<_, JsValue> {
            Ok(secret_array!(u, 32, "ssk"))
        })
        .transpose()?;

    let data_to_decrypt = SecretVec::new(datatodecrypt.to_vec());

    let decrypted = decrypt_data(
        ivk.as_ref(),
        epk.as_ref(),
        &data_to_decrypt,
        ssk.as_ref(),
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(Uint8Array::from(decrypted.expose_secret().as_slice()))
}