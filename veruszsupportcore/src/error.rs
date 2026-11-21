//! The library's one error type, and the messages its checks fail with.

use std::fmt;

use crate::limits::ZIP32_HARDENED_KEY_LIMIT;

/// The one error type of the library, with the same two kinds on every
/// platform. Its message is what the caller sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerusZSupportError {
    /// The library rejected the arguments before any cryptography ran: one is
    /// missing, extra, the wrong length or out of range. The call must change
    /// to succeed.
    InvalidInput(String),
    /// The cryptography failed: a key that is not valid, the wrong key or a
    /// changed ciphertext.
    Crypto(String),
}

impl VerusZSupportError {
    /// The kind's name, the same on every platform.
    pub fn kind(&self) -> &'static str {
        match self {
            VerusZSupportError::InvalidInput(_) => "InvalidInput",
            VerusZSupportError::Crypto(_) => "Crypto",
        }
    }

    /// The message, without the kind.
    pub fn message(&self) -> &str {
        match self {
            VerusZSupportError::InvalidInput(message) | VerusZSupportError::Crypto(message) => {
                message
            }
        }
    }
}

impl fmt::Display for VerusZSupportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for VerusZSupportError {}

pub(crate) fn invalid_input(message: impl Into<String>) -> VerusZSupportError {
    VerusZSupportError::InvalidInput(message.into())
}

pub(crate) fn wrong_length(field: &str, expected: usize) -> VerusZSupportError {
    invalid_input(format!("{field} must be exactly {expected} bytes"))
}

pub(crate) fn too_long(field: &str, max: usize) -> VerusZSupportError {
    invalid_input(format!("{field} must be at most {max} bytes"))
}

pub(crate) fn index_out_of_range(field: &str) -> VerusZSupportError {
    // Same wording as the daemon's z_getencryptionaddress.
    invalid_input(format!(
        "{field} must be an index between 0 and {}",
        ZIP32_HARDENED_KEY_LIMIT - 1
    ))
}

pub(crate) fn crypto_error(error: impl fmt::Display) -> VerusZSupportError {
    VerusZSupportError::Crypto(error.to_string())
}
