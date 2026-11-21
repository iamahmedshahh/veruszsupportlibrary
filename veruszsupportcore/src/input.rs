//! Reads what the bindings hand over: bytes into fixed-size arrays, checking
//! their length, and indices that came from JavaScript.

use secrecy::{ExposeSecret, Secret, SecretVec};

use crate::error::{index_out_of_range, wrong_length, VerusZSupportError};
use crate::limits::ZIP32_HARDENED_KEY_LIMIT;

/// Copies public bytes (epk, hash160 IDs, address bytes) into a fixed-size array.
pub(crate) fn public_array<const N: usize>(
    bytes: &[u8],
    field: &str,
) -> Result<[u8; N], VerusZSupportError> {
    bytes.try_into().map_err(|_| wrong_length(field, N))
}

/// Copies key material (ivk, ssk, spending key) into a fixed-size Secret,
/// which is wiped when dropped.
pub(crate) fn secret_array<const N: usize>(
    bytes: &SecretVec<u8>,
    field: &str,
) -> Result<Secret<[u8; N]>, VerusZSupportError> {
    public_array(bytes.expose_secret(), field).map(Secret::new)
}

/// verus_zfunc's hardened derivation asserts index < 2^31, so reject larger
/// ones before it can panic.
pub(crate) fn check_index(index: Option<u32>, field: &str) -> Result<(), VerusZSupportError> {
    if index.is_some_and(|index| index >= ZIP32_HARDENED_KEY_LIMIT) {
        return Err(index_out_of_range(field));
    }
    Ok(())
}

/// Reads an index that came from JavaScript, where every number is a double.
///
/// Both bindings would turn a bad number into a valid u32 without a word
/// (2^32 becomes 0, 1.5 becomes 1), so the web and mobile crates take the
/// index as f64 and check it here, the same way for both.
pub fn index_from_js(value: Option<f64>, field: &str) -> Result<Option<u32>, VerusZSupportError> {
    value
        .map(|number| {
            let is_index = number.fract() == 0.0
                && number >= 0.0
                && number < f64::from(ZIP32_HARDENED_KEY_LIMIT);
            if is_index {
                // Exact: a whole number below 2^31.
                Ok(number as u32)
            } else {
                Err(index_out_of_range(field))
            }
        })
        .transpose()
}
