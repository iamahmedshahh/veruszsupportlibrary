//! Every size and range the library checks, each taken from the standard
//! that sets it. Nothing else in the library writes these numbers: the checks
//! in this crate use them, and the web and mobile crates hand them to
//! JavaScript through `limits()`.

/// Child indices (hdIndex, encryptionIndex) are hardened, so they must be
/// below 2^31. Same name and value as the daemon's, in
/// src/zcash/address/zip32.h (ZIP 32).
pub const ZIP32_HARDENED_KEY_LIMIT: u32 = 0x8000_0000;

/// Seed lengths, as the daemon's z_getencryptionaddress takes them: a 32 or
/// 64 byte value.
pub const SEED_LENGTHS: [usize; 2] = [32, 64];

/// An extended spending key, serialized as ZIP 32 sets out. The daemon's
/// ZIP32_XSK_SIZE.
pub const SPENDING_KEY_BYTES: usize = 169;

/// A Sapling payment address: an 11-byte diversifier and a 32-byte pk_d
/// (Zcash protocol spec, "Sapling Payment Addresses").
pub const PAYMENT_ADDRESS_BYTES: usize = 43;

/// A VerusID: the hash160 inside an i-address (CIdentityID is a uint160).
pub const IDENTITY_ID_BYTES: usize = 20;

/// An incoming viewing key (a uint256 in the daemon's
/// SaplingIncomingViewingKey).
pub const IVK_BYTES: usize = 32;

/// An ephemeral public key: one encoded Jubjub point (a uint256 from the
/// daemon's CVDXFEncryptor::GetEPK).
pub const EPK_BYTES: usize = 32;

/// A symmetric key: the ChaCha20-Poly1305 key (RFC 8439).
pub const SSK_BYTES: usize = 32;

/// The ChaCha20-Poly1305 tag at the end of every ciphertext (RFC 8439).
pub const TAG_BYTES: usize = 16;

/// The most data one call encrypts. The daemon has no limit for encrypting
/// as such; this is the cap its signdata puts on data it reads,
/// MAX_TX_SIZE_AFTER_SAPLING / 2.
pub const MAX_PAYLOAD_BYTES: usize = 1_000_000;

/// A DataDescriptor salt: a uint256, the size the daemon makes
/// (CSaltedData::FreshSalt).
pub const SALT_BYTES: usize = 32;

/// The limits above, in the shape the bindings hand to JavaScript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest hdIndex or encryptionIndex.
    pub max_index: u32,
    pub seed_lengths: [u32; 2],
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

/// Every value fits in a u32, which JavaScript numbers hold exactly.
pub const LIMITS: Limits = Limits {
    max_index: ZIP32_HARDENED_KEY_LIMIT - 1,
    seed_lengths: [SEED_LENGTHS[0] as u32, SEED_LENGTHS[1] as u32],
    spending_key_bytes: SPENDING_KEY_BYTES as u32,
    payment_address_bytes: PAYMENT_ADDRESS_BYTES as u32,
    identity_id_bytes: IDENTITY_ID_BYTES as u32,
    ivk_bytes: IVK_BYTES as u32,
    epk_bytes: EPK_BYTES as u32,
    ssk_bytes: SSK_BYTES as u32,
    tag_bytes: TAG_BYTES as u32,
    max_payload_bytes: MAX_PAYLOAD_BYTES as u32,
    salt_bytes: SALT_BYTES as u32,
};
