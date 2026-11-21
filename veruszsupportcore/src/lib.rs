//! Shared Rust code for every platform: checks the inputs, then calls verus_zfunc.
//!
//! The web crate (wasm-bindgen) and the mobile crate (uniffi) only convert
//! their own byte types to and from the types here, so both platforms accept
//! the same inputs and report the same errors, with the same messages.
//!
//! Every check that can run before the cryptography runs here and fails with
//! `InvalidInput`. What only the cryptography can tell (a key that is not
//! valid, the wrong key, a changed ciphertext) comes back from verus_zfunc as
//! `Crypto`.

use sapling_crypto::PaymentAddress;
use secrecy::{ExposeSecret, Secret, SecretVec};

pub use verus_zfunc::{ChannelKeys, EncryptedPayload};

mod error;
mod input;
pub mod limits;

pub use error::VerusZSupportError;
pub use input::index_from_js;

use error::{crypto_error, invalid_input, too_long};
use input::{check_index, public_array, secret_array};
use limits::{
    EPK_BYTES, IDENTITY_ID_BYTES, IVK_BYTES, MAX_PAYLOAD_BYTES, PAYMENT_ADDRESS_BYTES, SALT_BYTES,
    SEED_LENGTHS, SPENDING_KEY_BYTES, SSK_BYTES, TAG_BYTES,
};

/// Derives the Sapling channel keys used for encryption and decryption, as
/// the daemon's z_getencryptionaddress does.
///
/// `seed` and `spending_key` are alternative key sources: pass exactly one.
/// `hd_index` picks the account under a seed, so it only goes with `seed`.
pub fn z_get_encryption_address(
    seed: Option<SecretVec<u8>>,
    spending_key: Option<SecretVec<u8>>,
    hd_index: Option<u32>,
    encryption_index: Option<u32>,
    from_id: Option<&[u8]>,
    to_id: Option<&[u8]>,
    return_secret: bool,
) -> Result<ChannelKeys, VerusZSupportError> {
    match (&seed, &spending_key) {
        (Some(_), Some(_)) => return Err(invalid_input("seed and spendingKey cannot both be set")),
        (None, None) => return Err(invalid_input("seed or spendingKey is required")),
        _ => {}
    }
    if seed
        .as_ref()
        .is_some_and(|seed| !SEED_LENGTHS.contains(&seed.expose_secret().len()))
    {
        return Err(invalid_input(format!(
            "seed must be {} or {} bytes",
            SEED_LENGTHS[0], SEED_LENGTHS[1]
        )));
    }
    if spending_key.is_some() && hd_index.is_some() {
        return Err(invalid_input("hdIndex can only be used with seed"));
    }
    check_index(hd_index, "hdIndex")?;
    check_index(encryption_index, "encryptionIndex")?;

    let spending_key: Option<Secret<[u8; SPENDING_KEY_BYTES]>> = spending_key
        .map(|bytes| secret_array(&bytes, "spendingKey"))
        .transpose()?;
    let from_id: Option<[u8; IDENTITY_ID_BYTES]> = from_id
        .map(|bytes| public_array(bytes, "fromId"))
        .transpose()?;
    let to_id: Option<[u8; IDENTITY_ID_BYTES]> =
        to_id.map(|bytes| public_array(bytes, "toId")).transpose()?;

    verus_zfunc::z_getencryptionaddress(
        seed.as_ref(),
        spending_key.as_ref(),
        hd_index,
        encryption_index,
        from_id.as_ref(),
        to_id.as_ref(),
        return_secret,
    )
    .map_err(crypto_error)
}

/// A fresh DataDescriptor salt, from the random source verus_zfunc uses for
/// its keys: the OS on Android and iOS, crypto.getRandomValues on the web. So
/// apps need no random-number polyfill of their own.
pub fn fresh_salt() -> Result<[u8; SALT_BYTES], VerusZSupportError> {
    let mut salt = [0u8; SALT_BYTES];
    getrandom::getrandom(&mut salt).map_err(crypto_error)?;
    Ok(salt)
}

/// Encrypts `data` to a Sapling payment address.
pub fn encrypt_data(
    address: &[u8],
    data: SecretVec<u8>,
    return_ssk: bool,
) -> Result<EncryptedPayload, VerusZSupportError> {
    let address: [u8; PAYMENT_ADDRESS_BYTES] = public_array(address, "address")?;
    let payment_address = PaymentAddress::from_bytes(&address)
        .ok_or_else(|| invalid_input("address is not a valid Sapling payment address"))?;

    if data.expose_secret().len() > MAX_PAYLOAD_BYTES {
        return Err(too_long("data", MAX_PAYLOAD_BYTES));
    }

    verus_zfunc::encrypt_data(&payment_address, &data, return_ssk).map_err(crypto_error)
}

/// Decrypts `encrypted_data` with exactly one key: `ivk` (with `epk`) or `ssk`.
///
/// `epk` is ignored with `ssk`, so a whole DataDescriptor can be passed as is.
pub fn decrypt_data(
    ivk: Option<SecretVec<u8>>,
    epk: Option<&[u8]>,
    encrypted_data: SecretVec<u8>,
    ssk: Option<SecretVec<u8>>,
) -> Result<SecretVec<u8>, VerusZSupportError> {
    // exactly one key: ivk (with epk) or ssk — never silently prefer one
    match (&ivk, &ssk) {
        (Some(_), Some(_)) => return Err(invalid_input("ivk and ssk cannot both be set")),
        (None, None) => return Err(invalid_input("ivk or ssk is required")),
        _ => {}
    }
    // epk is only meaningful with ivk; drop it in ssk mode
    let epk = if ssk.is_some() { None } else { epk };
    if ivk.is_some() && epk.is_none() {
        return Err(invalid_input("epk is required with ivk"));
    }

    // A ciphertext is at least its tag; anything shorter was never one.
    let length = encrypted_data.expose_secret().len();
    if length < TAG_BYTES {
        return Err(invalid_input(format!(
            "encryptedData must be at least {TAG_BYTES} bytes"
        )));
    }
    if length > MAX_PAYLOAD_BYTES + TAG_BYTES {
        return Err(too_long("encryptedData", MAX_PAYLOAD_BYTES + TAG_BYTES));
    }

    let ivk: Option<Secret<[u8; IVK_BYTES]>> =
        ivk.map(|bytes| secret_array(&bytes, "ivk")).transpose()?;
    let epk: Option<[u8; EPK_BYTES]> = epk.map(|bytes| public_array(bytes, "epk")).transpose()?;
    let ssk: Option<Secret<[u8; SSK_BYTES]>> =
        ssk.map(|bytes| secret_array(&bytes, "ssk")).transpose()?;

    verus_zfunc::decrypt_data(ivk.as_ref(), epk.as_ref(), &encrypted_data, ssk.as_ref())
        .map_err(crypto_error)
}
