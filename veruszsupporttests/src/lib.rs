//! Values the tests share. The tests are in tests/, one file per crate:
//! core.rs (veruszsupportcore), mobile.rs (veruszsupportmobile) and web.rs
//! (veruszsupportweb).

/// The known vector, also in test/suite.mjs: SEED with FROM_ID and TO_ID, at
/// hdIndex 0 and encryptionIndex 0, derives ADDRESS and IVK.
pub const SEED: [u8; 32] = [0xaa; 32];

/// i5f5njYtso65186mo5WHMkRme9YG6hrZE2
pub const FROM_ID: &str = "0b5c956f351c1030e3b4085ec1e65564bde7289e";

/// i3bCS2hfQXktHXHmXEAxKPeby5cb6Px6Le
pub const TO_ID: &str = "01430cf819f4f3890c186526e3bb501e2373f72e";

pub const ADDRESS: &str =
    "cef7e26edcb3fe36d7963026bc63e034302ae7a06dd63fba3d145b0e901bab84a619aeb61d5fa4722188a7";

pub const IVK: &str = "f3bad47c876d722884f991620f3c8b47bd11d351256a62a54cd27fe2093aca00";

/// Numbers that a u32 binding would quietly turn into another index: 2^32
/// becomes 0, 1.5 becomes 1 and -1 becomes 4294967295.
pub const WRAPPING_INDICES: [f64; 3] = [4_294_967_296.0, 1.5, -1.0];

/// What the library says about a refused hdIndex, in the daemon's words.
pub const HD_INDEX_REFUSED: &str = "hdIndex must be an index between 0 and 2147483647";

/// What verus_zfunc says when the key or the encrypted data is wrong.
pub const DECRYPTION_FAILED: &str = "Decryption failed. Key or ciphertext may be incorrect.";

/// Bytes as lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hex back to bytes. Panics on bad hex: the tests only pass constants.
pub fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}
