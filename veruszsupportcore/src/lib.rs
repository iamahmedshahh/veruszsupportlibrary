//! shared Rust code by every platform: checks the inputs, then calls verus_zfunc.
//!
//! The web crate (wasm-bindgen) and the mobile crate (uniffi) only convert
//! their own byte types to and from the types here, so both platforms accept
//! the same inputs and report the same errors.

use std::fmt;

use sapling_crypto::PaymentAddress;
use secrecy::{ExposeSecret, Secret, SecretVec};

pub use verus_zfunc::{ChannelKeys, EncryptedPayload};

/// Upper bound on plaintext crossing the boundary. Policy value — tune to your largest real payload.
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024; // 1 MiB
/// ChaCha20Poly1305 tag length added to every ciphertext.
const AEAD_TAG_BYTES: usize = 16;
/// ZIP-32 hardened indices must be < 2^31; verus_zfunc's ChildIndex::hardened asserts this (panic).
const HARDENED_LIMIT: u32 = 1 << 31;

/// The one error type of the library. Its message is what the caller sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZSupportError {
    /// The caller passed a bad value. The call must change to succeed.
    InvalidInput(String),
    /// verus_zfunc failed, for example a wrong key or a changed ciphertext.
    Crypto(String),
}

impl fmt::Display for ZSupportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZSupportError::InvalidInput(message) | ZSupportError::Crypto(message) => {
                f.write_str(message)
            }
        }
    }
}

impl std::error::Error for ZSupportError {}

fn invalid_input(message: &str) -> ZSupportError {
    ZSupportError::InvalidInput(message.to_string())
}

fn invalid_length(field: &str, expected: usize) -> ZSupportError {
    ZSupportError::InvalidInput(format!(
        "INVALID_LENGTH: {field} must be exactly {expected} bytes"
    ))
}

fn crypto_error(error: impl fmt::Display) -> ZSupportError {
    ZSupportError::Crypto(error.to_string())
}

/// Copies public bytes (epk, hash160 IDs, address bytes) into a fixed-size array.
fn public_array<const N: usize>(bytes: &[u8], field: &str) -> Result<[u8; N], ZSupportError> {
    bytes.try_into().map_err(|_| invalid_length(field, N))
}

/// Copies key material (ivk, ssk, spending key) into a fixed-size Secret,
/// which is wiped when dropped.
fn secret_array<const N: usize>(
    bytes: &SecretVec<u8>,
    field: &str,
) -> Result<Secret<[u8; N]>, ZSupportError> {
    public_array(bytes.expose_secret(), field).map(Secret::new)
}

/// Derives the Sapling channel keys used for encryption and decryption.
///
/// `seed` and `spending_key` are alternative key sources: pass one of them.
pub fn z_get_encryptionaddress(
    seed: Option<SecretVec<u8>>,
    spending_key: Option<SecretVec<u8>>,
    hd_index: Option<u32>,
    encryption_index: Option<u32>,
    from_id: Option<&[u8]>,
    to_id: Option<&[u8]>,
    return_secret: bool,
) -> Result<ChannelKeys, ZSupportError> {
    // seed and spendingKey are alternative key sources — reject ambiguity
    if seed.is_some() && spending_key.is_some() {
        return Err(invalid_input(
            "Provide either seed or spendingKey, not both",
        ));
    }
    // verus_zfunc's hardened derivation asserts index < 2^31 — reject before it can panic
    if hd_index.is_some_and(|i| i >= HARDENED_LIMIT) {
        return Err(invalid_input("hdIndex must be less than 2^31"));
    }
    if encryption_index.is_some_and(|i| i >= HARDENED_LIMIT) {
        return Err(invalid_input("encryptionIndex must be less than 2^31"));
    }

    let spending_key: Option<Secret<[u8; 169]>> = spending_key
        .map(|bytes| secret_array(&bytes, "spending_key"))
        .transpose()?;
    let from_id: Option<[u8; 20]> = from_id
        .map(|bytes| public_array(bytes, "from_id"))
        .transpose()?;
    let to_id: Option<[u8; 20]> = to_id
        .map(|bytes| public_array(bytes, "to_id"))
        .transpose()?;

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

/// Encrypts `data` to a Sapling payment address (43 bytes).
pub fn encrypt_v_data(
    address: &[u8],
    data: SecretVec<u8>,
    return_ssk: bool,
) -> Result<EncryptedPayload, ZSupportError> {
    let address: [u8; 43] = public_array(address, "address")?;
    let payment_address = PaymentAddress::from_bytes(&address)
        .ok_or_else(|| invalid_input("Invalid PaymentAddress bytes"))?;

    if data.expose_secret().len() > MAX_PAYLOAD_BYTES {
        return Err(invalid_input("data exceeds maximum payload size"));
    }

    verus_zfunc::encrypt_data(&payment_address, &data, return_ssk).map_err(crypto_error)
}

/// Decrypts `data_to_decrypt` with exactly one key: `ivk` (with `epk`) or `ssk`.
pub fn decrypt_v_data(
    ivk: Option<SecretVec<u8>>,
    epk: Option<&[u8]>,
    data_to_decrypt: SecretVec<u8>,
    ssk: Option<SecretVec<u8>>,
) -> Result<SecretVec<u8>, ZSupportError> {
    // exactly one key: ivk (with epk) or ssk — never silently prefer one
    if ivk.is_some() && ssk.is_some() {
        return Err(invalid_input(
            "Provide either ivk (with epk) or ssk, not both",
        ));
    }
    // epk is only meaningful with ivk; drop it in ssk mode
    let epk = if ssk.is_some() { None } else { epk };

    if data_to_decrypt.expose_secret().len() > MAX_PAYLOAD_BYTES + AEAD_TAG_BYTES {
        return Err(invalid_input("datatodecrypt exceeds maximum payload size"));
    }

    let ivk: Option<Secret<[u8; 32]>> = ivk.map(|bytes| secret_array(&bytes, "ivk")).transpose()?;
    let epk: Option<[u8; 32]> = epk.map(|bytes| public_array(bytes, "epk")).transpose()?;
    let ssk: Option<Secret<[u8; 32]>> = ssk.map(|bytes| secret_array(&bytes, "ssk")).transpose()?;

    verus_zfunc::decrypt_data(ivk.as_ref(), epk.as_ref(), &data_to_decrypt, ssk.as_ref())
        .map_err(crypto_error)
}
