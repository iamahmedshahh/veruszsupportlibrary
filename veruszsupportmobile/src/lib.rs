//! The mobile boundary: converts the bytes React Native sends to Rust and
//! back. The input checks and the cryptography live in veruszsupportcore,
//! shared with the web crate.
//!
//! Apps call these through veruszsupportlib (src/engine.native.ts), never
//! directly.

use std::fmt;

use secrecy::{ExposeSecret, SecretVec};
use veruszsupportcore::limits::LIMITS;

uniffi::setup_scaffolding!();

/// The error React Native callers catch. Same two kinds, and the same
/// messages, as veruszsupportcore and the web package.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum VerusZSupportError {
    /// The library rejected the arguments before any cryptography ran. The
    /// call must change to succeed.
    InvalidInput { message: String },
    /// The cryptography failed: a key that is not valid, the wrong key or a
    /// changed ciphertext.
    Crypto { message: String },
}

impl fmt::Display for VerusZSupportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerusZSupportError::InvalidInput { message }
            | VerusZSupportError::Crypto { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for VerusZSupportError {}

impl From<veruszsupportcore::VerusZSupportError> for VerusZSupportError {
    fn from(error: veruszsupportcore::VerusZSupportError) -> Self {
        match error {
            veruszsupportcore::VerusZSupportError::InvalidInput(message) => {
                VerusZSupportError::InvalidInput { message }
            }
            veruszsupportcore::VerusZSupportError::Crypto(message) => {
                VerusZSupportError::Crypto { message }
            }
        }
    }
}

/// Sapling channel keys. `spending_key` is set only when `return_secret` was true.
///
/// No Debug: printing it would print the keys.
#[derive(uniffi::Record)]
pub struct ChannelKeys {
    pub address: Vec<u8>,
    pub ivk: Vec<u8>,
    pub extfvk: Vec<u8>,
    pub spending_key: Option<Vec<u8>>,
}

/// Encrypted data. `symmetric_key` is set only when `return_ssk` was true.
///
/// No Debug: printing it would print the key.
#[derive(uniffi::Record)]
pub struct EncryptedPayload {
    pub ephemeral_public_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub symmetric_key: Option<Vec<u8>>,
}

/// The sizes and ranges the library checks, from veruszsupportcore's limits.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Limits {
    /// The largest hdIndex or encryptionIndex.
    pub max_index: u32,
    pub seed_lengths: Vec<u32>,
    pub spending_key_bytes: u32,
    pub payment_address_bytes: u32,
    pub identity_id_bytes: u32,
    pub ivk_bytes: u32,
    pub epk_bytes: u32,
    pub ssk_bytes: u32,
    pub tag_bytes: u32,
    pub max_payload_bytes: u32,
    pub salt_bytes: u32,
}

/// The sizes and ranges the library checks.
#[uniffi::export]
pub fn limits() -> Limits {
    Limits {
        max_index: LIMITS.max_index,
        seed_lengths: LIMITS.seed_lengths.to_vec(),
        spending_key_bytes: LIMITS.spending_key_bytes,
        payment_address_bytes: LIMITS.payment_address_bytes,
        identity_id_bytes: LIMITS.identity_id_bytes,
        ivk_bytes: LIMITS.ivk_bytes,
        epk_bytes: LIMITS.epk_bytes,
        ssk_bytes: LIMITS.ssk_bytes,
        tag_bytes: LIMITS.tag_bytes,
        max_payload_bytes: LIMITS.max_payload_bytes,
        salt_bytes: LIMITS.salt_bytes,
    }
}

/// A fresh DataDescriptor salt, from the OS random source.
#[uniffi::export]
pub fn fresh_salt() -> Result<Vec<u8>, VerusZSupportError> {
    Ok(veruszsupportcore::fresh_salt()?.to_vec())
}

/// Derives the Sapling channel keys used for encryption and decryption.
///
/// The indices are JS numbers, checked in veruszsupportcore before use.
#[uniffi::export]
pub fn z_get_encryption_address(
    seed: Option<Vec<u8>>,
    spending_key: Option<Vec<u8>>,
    hd_index: Option<f64>,
    encryption_index: Option<f64>,
    from_id: Option<Vec<u8>>,
    to_id: Option<Vec<u8>>,
    return_secret: bool,
) -> Result<ChannelKeys, VerusZSupportError> {
    
    let seed = seed.map(SecretVec::new);
    let spending_key = spending_key.map(SecretVec::new);
    let hd_index = veruszsupportcore::index_from_js(hd_index, "hdIndex")?;
    let encryption_index = veruszsupportcore::index_from_js(encryption_index, "encryptionIndex")?;

    let keys = veruszsupportcore::z_get_encryption_address(
        seed,
        spending_key,
        hd_index,
        encryption_index,
        from_id.as_deref(),
        to_id.as_deref(),
        return_secret,
    )?;

    Ok(ChannelKeys {
        address: keys.address.to_bytes().to_vec(),
        ivk: keys.ivk_bytes.expose_secret().to_vec(),
        extfvk: keys.extfvk_bytes.expose_secret().to_vec(),
        spending_key: keys
            .spending_key_bytes
            .as_ref()
            .map(|sk| sk.expose_secret().to_vec()),
    })
}

/// Encrypts `data` to a Sapling payment address.
#[uniffi::export]
pub fn encrypt_data(
    address: Vec<u8>,
    data: Vec<u8>,
    return_ssk: bool,
) -> Result<EncryptedPayload, VerusZSupportError> {
    let payload = veruszsupportcore::encrypt_data(&address, SecretVec::new(data), return_ssk)?;

    Ok(EncryptedPayload {
        ephemeral_public_key: payload.ephemeral_public_key.to_vec(),
        symmetric_key: payload
            .symmetric_key
            .as_ref()
            .map(|ssk| ssk.expose_secret().to_vec()),
        encrypted_data: payload.encrypted_data,
    })
}

/// Decrypts `encrypted_data` with exactly one key: `ivk` (with `epk`) or `ssk`.
#[uniffi::export]
pub fn decrypt_data(
    ivk: Option<Vec<u8>>,
    epk: Option<Vec<u8>>,
    encrypted_data: Vec<u8>,
    ssk: Option<Vec<u8>>,
) -> Result<Vec<u8>, VerusZSupportError> {
    let decrypted = veruszsupportcore::decrypt_data(
        ivk.map(SecretVec::new),
        epk.as_deref(),
        SecretVec::new(encrypted_data),
        ssk.map(SecretVec::new),
    )?;

    Ok(decrypted.expose_secret().clone())
}
