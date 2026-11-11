//! The mobile boundary: converts the bytes React Native sends to Rust and
//! back. The input checks and the cryptography live in veruszsupportcore,
//! shared with the web crate.

use std::fmt;

use secrecy::{ExposeSecret, SecretVec};

uniffi::setup_scaffolding!();

/// The error React Native callers catch. Same two kinds as veruszsupportcore.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum ZSupportError {
    /// The caller passed a bad value. The call must change to succeed.
    InvalidInput { message: String },
    /// verus_zfunc failed, for example a wrong key or a changed ciphertext.
    Crypto { message: String },
}

impl fmt::Display for ZSupportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZSupportError::InvalidInput { message } | ZSupportError::Crypto { message } => {
                f.write_str(message)
            }
        }
    }
}

impl std::error::Error for ZSupportError {}

impl From<veruszsupportcore::ZSupportError> for ZSupportError {
    fn from(error: veruszsupportcore::ZSupportError) -> Self {
        match error {
            veruszsupportcore::ZSupportError::InvalidInput(message) => {
                ZSupportError::InvalidInput { message }
            }
            veruszsupportcore::ZSupportError::Crypto(message) => ZSupportError::Crypto { message },
        }
    }
}

/// Sapling channel keys. `spending_key` is set only when `return_secret` was true.
#[derive(Debug, uniffi::Record)]
pub struct ChannelKeys {
    pub address: Vec<u8>,
    pub ivk: Vec<u8>,
    pub extfvk: Vec<u8>,
    pub spending_key: Option<Vec<u8>>,
}

/// Encrypted data. `symmetric_key` is set only when `return_ssk` was true.
#[derive(Debug, uniffi::Record)]
pub struct EncryptedPayload {
    pub ephemeral_public_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub symmetric_key: Option<Vec<u8>>,
}

// generate channel keys for encryption and decryption

#[uniffi::export]
pub fn z_get_encryptionaddress(
    seed: Option<Vec<u8>>,
    spending_key: Option<Vec<u8>>,
    hd_index: Option<u32>,
    encryption_index: Option<u32>,
    from_id: Option<Vec<u8>>,
    to_id: Option<Vec<u8>>,
    return_secret: bool,
) -> Result<ChannelKeys, ZSupportError> {
    let keys = veruszsupportcore::z_get_encryptionaddress(
        seed.map(SecretVec::new),
        spending_key.map(SecretVec::new),
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

// encrypt data buffer

#[uniffi::export]
pub fn encrypt_v_data(
    address: Vec<u8>,
    data: Vec<u8>,
    return_ssk: bool,
) -> Result<EncryptedPayload, ZSupportError> {
    let payload = veruszsupportcore::encrypt_v_data(&address, SecretVec::new(data), return_ssk)?;

    Ok(EncryptedPayload {
        ephemeral_public_key: payload.ephemeral_public_key.to_vec(),
        symmetric_key: payload
            .symmetric_key
            .as_ref()
            .map(|ssk| ssk.expose_secret().to_vec()),
        encrypted_data: payload.encrypted_data,
    })
}

// decrypt_data

#[uniffi::export]
pub fn decrypt_v_data(
    ivk: Option<Vec<u8>>,
    epk: Option<Vec<u8>>,
    datatodecrypt: Vec<u8>,
    ssk: Option<Vec<u8>>,
) -> Result<Vec<u8>, ZSupportError> {
    let decrypted = veruszsupportcore::decrypt_v_data(
        ivk.map(SecretVec::new),
        epk.as_deref(),
        SecretVec::new(datatodecrypt),
        ssk.map(SecretVec::new),
    )?;

    Ok(decrypted.expose_secret().clone())
}
