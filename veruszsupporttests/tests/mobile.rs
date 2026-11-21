//! veruszsupportmobile: the exports React Native calls through uniffi. They
//! must give what the core gives, with the core's errors and messages.

#![cfg(not(target_arch = "wasm32"))]

use veruszsupportcore::limits::LIMITS;
use veruszsupportmobile::{
    decrypt_data, encrypt_data, fresh_salt, limits, z_get_encryption_address, ChannelKeys,
    VerusZSupportError,
};
use veruszsupporttests::{
    from_hex, to_hex, ADDRESS, DECRYPTION_FAILED, FROM_ID, HD_INDEX_REFUSED, IVK, SEED, TO_ID,
    WRAPPING_INDICES,
};

/// Keys from SEED for the two IDs, with indices as JavaScript numbers.
fn derive(hd_index: Option<f64>, return_secret: bool) -> Result<ChannelKeys, VerusZSupportError> {
    z_get_encryption_address(
        Some(SEED.to_vec()),
        None,
        hd_index,
        Some(0.0),
        Some(from_hex(FROM_ID)),
        Some(from_hex(TO_ID)),
        return_secret,
    )
}

fn invalid_input(message: &str) -> VerusZSupportError {
    VerusZSupportError::InvalidInput {
        message: message.into(),
    }
}

#[test]
fn derives_the_known_vector() {
    let keys = derive(Some(0.0), false).unwrap();

    assert_eq!(to_hex(&keys.address), ADDRESS);
    assert_eq!(to_hex(&keys.ivk), IVK);
    assert_eq!(keys.extfvk.len(), 169);
    assert_eq!(keys.spending_key, None);
}

#[test]
fn returns_the_spending_key_only_when_asked() {
    let keys = derive(None, true).unwrap();

    assert_eq!(keys.spending_key.map(|key| key.len()), Some(169));
}

#[test]
fn refuses_indices_that_a_u32_would_wrap() {
    for index in WRAPPING_INDICES {
        assert_eq!(
            derive(Some(index), false).err(),
            Some(invalid_input(HD_INDEX_REFUSED)),
            "{index} was taken"
        );
    }
}

#[test]
fn passes_the_core_errors_on_with_their_messages() {
    let short_seed =
        z_get_encryption_address(Some(vec![7; 31]), None, None, None, None, None, false);
    let short_ivk = decrypt_data(Some(vec![0; 31]), Some(vec![0; 32]), vec![0; 16], None);

    assert_eq!(
        short_seed.err(),
        Some(invalid_input("seed must be 32 or 64 bytes"))
    );
    assert_eq!(
        short_ivk.err(),
        Some(invalid_input("ivk must be exactly 32 bytes"))
    );
}

#[test]
fn encrypts_and_decrypts_with_the_ivk_and_with_the_ssk() {
    let keys = derive(None, false).unwrap();
    let payload = encrypt_data(keys.address, b"saved sign in".to_vec(), true).unwrap();
    let ssk = payload.symmetric_key.clone().expect("asked for");

    let with_ivk = decrypt_data(
        Some(keys.ivk),
        Some(payload.ephemeral_public_key.clone()),
        payload.encrypted_data.clone(),
        None,
    )
    .unwrap();
    let with_ssk = decrypt_data(None, None, payload.encrypted_data, Some(ssk)).unwrap();

    assert_eq!(with_ivk, b"saved sign in");
    assert_eq!(with_ssk, b"saved sign in");
}

#[test]
fn a_changed_ciphertext_is_a_crypto_error() {
    let keys = derive(None, false).unwrap();
    let mut payload = encrypt_data(keys.address, b"hello".to_vec(), false).unwrap();
    payload.encrypted_data[0] ^= 1;

    let result = decrypt_data(
        Some(keys.ivk),
        Some(payload.ephemeral_public_key),
        payload.encrypted_data,
        None,
    );

    assert_eq!(
        result.err(),
        Some(VerusZSupportError::Crypto {
            message: DECRYPTION_FAILED.into()
        })
    );
}

#[test]
fn errors_print_their_message() {
    assert_eq!(invalid_input("hello").to_string(), "hello");
}

#[test]
fn fresh_salts_are_salt_sized_and_differ() {
    let first = fresh_salt().unwrap();
    let second = fresh_salt().unwrap();

    assert_eq!(first.len(), LIMITS.salt_bytes as usize);
    assert_ne!(first, second);
}

#[test]
fn limits_are_the_cores() {
    let limits = limits();

    assert_eq!(limits.max_index, LIMITS.max_index);
    assert_eq!(limits.seed_lengths, LIMITS.seed_lengths.to_vec());
    assert_eq!(limits.spending_key_bytes, LIMITS.spending_key_bytes);
    assert_eq!(limits.payment_address_bytes, LIMITS.payment_address_bytes);
    assert_eq!(limits.identity_id_bytes, LIMITS.identity_id_bytes);
    assert_eq!(limits.ivk_bytes, LIMITS.ivk_bytes);
    assert_eq!(limits.epk_bytes, LIMITS.epk_bytes);
    assert_eq!(limits.ssk_bytes, LIMITS.ssk_bytes);
    assert_eq!(limits.tag_bytes, LIMITS.tag_bytes);
    assert_eq!(limits.max_payload_bytes, LIMITS.max_payload_bytes);
    assert_eq!(limits.salt_bytes, LIMITS.salt_bytes);
}
