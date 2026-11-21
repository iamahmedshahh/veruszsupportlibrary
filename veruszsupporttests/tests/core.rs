//! veruszsupportcore: every check before the cryptography, and what comes back
//! from verus_zfunc.

#![cfg(not(target_arch = "wasm32"))]

use secrecy::{ExposeSecret, SecretVec};
use veruszsupportcore::limits::{
    LIMITS, MAX_PAYLOAD_BYTES, SALT_BYTES, SPENDING_KEY_BYTES, TAG_BYTES, ZIP32_HARDENED_KEY_LIMIT,
};
use veruszsupportcore::{
    decrypt_data, encrypt_data, fresh_salt, index_from_js, z_get_encryption_address, ChannelKeys,
    VerusZSupportError,
};
use veruszsupporttests::{
    from_hex, to_hex, ADDRESS, DECRYPTION_FAILED, FROM_ID, HD_INDEX_REFUSED, IVK, SEED, TO_ID,
    WRAPPING_INDICES,
};

fn secret(bytes: &[u8]) -> SecretVec<u8> {
    SecretVec::new(bytes.to_vec())
}

/// Keys from SEED for the two IDs, at the given indices.
fn derive(
    hd_index: Option<u32>,
    encryption_index: Option<u32>,
    return_secret: bool,
) -> ChannelKeys {
    z_get_encryption_address(
        Some(secret(&SEED)),
        None,
        hd_index,
        encryption_index,
        Some(&from_hex(FROM_ID)),
        Some(&from_hex(TO_ID)),
        return_secret,
    )
    .expect("keys from the known vector")
}

/// The channel address, as hex, for any seed, hdIndex and pair of IDs.
fn address_of(
    seed: &[u8],
    hd_index: Option<u32>,
    from_id: Option<&[u8]>,
    to_id: Option<&[u8]>,
) -> String {
    let keys = z_get_encryption_address(
        Some(secret(seed)),
        None,
        hd_index,
        None,
        from_id,
        to_id,
        false,
    )
    .expect("keys");
    to_hex(&keys.address.to_bytes())
}

/// The message of a call that must fail with InvalidInput.
fn invalid_input<T>(result: Result<T, VerusZSupportError>) -> String {
    match result {
        Err(VerusZSupportError::InvalidInput(message)) => message,
        Err(other) => panic!("expected InvalidInput, got {other:?}"),
        Ok(_) => panic!("expected InvalidInput, got a result"),
    }
}

/// The message of a call that must fail with Crypto.
fn crypto<T>(result: Result<T, VerusZSupportError>) -> String {
    match result {
        Err(VerusZSupportError::Crypto(message)) => message,
        Err(other) => panic!("expected Crypto, got {other:?}"),
        Ok(_) => panic!("expected Crypto, got a result"),
    }
}

#[test]
fn derives_the_known_vector() {
    let keys = derive(Some(0), Some(0), false);

    assert_eq!(to_hex(&keys.address.to_bytes()), ADDRESS);
    assert_eq!(to_hex(keys.ivk_bytes.expose_secret()), IVK);
    assert!(keys.spending_key_bytes.is_none());
}

#[test]
fn missing_indices_are_index_0() {
    let keys = derive(None, None, false);

    assert_eq!(to_hex(&keys.address.to_bytes()), ADDRESS);
}

#[test]
fn takes_a_64_byte_seed() {
    let seed = [0xbb; 64];
    let from_id = from_hex(FROM_ID);
    let to_id = from_hex(TO_ID);

    let first = address_of(&seed, None, Some(&from_id), Some(&to_id));
    let again = address_of(&seed, None, Some(&from_id), Some(&to_id));

    assert_eq!(first, again);
    assert_ne!(first, ADDRESS);
}

#[test]
fn each_hd_index_is_its_own_account() {
    let from_id = from_hex(FROM_ID);
    let to_id = from_hex(TO_ID);

    let account_1 = address_of(&SEED, Some(1), Some(&from_id), Some(&to_id));
    let account_2 = address_of(&SEED, Some(2), Some(&from_id), Some(&to_id));

    assert_ne!(account_1, ADDRESS);
    assert_ne!(account_1, account_2);
    assert_eq!(
        account_1,
        address_of(&SEED, Some(1), Some(&from_id), Some(&to_id))
    );
}

#[test]
fn a_missing_to_id_adds_nothing_to_the_channel() {
    // As in the daemon: a missing fromId hashes as one zero byte, a missing
    // toId as nothing at all, so no toId is not the same as 20 zero bytes.
    let from_id = from_hex(FROM_ID);

    let without = address_of(&SEED, None, Some(&from_id), None);
    let with_zeros = address_of(&SEED, None, Some(&from_id), Some(&[0; 20]));

    assert_ne!(without, ADDRESS);
    assert_ne!(without, with_zeros);
    assert_eq!(without, address_of(&SEED, None, Some(&from_id), None));
}

#[test]
fn returns_a_spending_key_only_when_asked_and_takes_it_back() {
    let keys = derive(None, None, true);
    let spending_key = keys
        .spending_key_bytes
        .as_ref()
        .expect("asked for")
        .expose_secret()
        .to_vec();

    let from_key = z_get_encryption_address(
        None,
        Some(secret(&spending_key)),
        None,
        None,
        None,
        None,
        false,
    );

    assert_eq!(spending_key.len(), SPENDING_KEY_BYTES);
    assert!(from_key.is_ok());
}

#[test]
fn index_from_js_takes_only_whole_numbers_below_2_pow_31() {
    assert_eq!(index_from_js(None, "hdIndex"), Ok(None));
    assert_eq!(index_from_js(Some(0.0), "hdIndex"), Ok(Some(0)));
    assert_eq!(
        index_from_js(Some(2_147_483_647.0), "hdIndex"),
        Ok(Some(2_147_483_647))
    );

    let refused = WRAPPING_INDICES
        .into_iter()
        .chain([2_147_483_648.0, f64::NAN, f64::INFINITY]);
    for index in refused {
        assert_eq!(
            invalid_input(index_from_js(Some(index), "hdIndex")),
            HD_INDEX_REFUSED,
            "{index} was taken"
        );
    }
}

#[test]
fn key_source_mistakes_are_invalid_input() {
    let neither = z_get_encryption_address(None, None, None, None, None, None, false);
    let both = z_get_encryption_address(
        Some(secret(&SEED)),
        Some(secret(&[0; SPENDING_KEY_BYTES])),
        None,
        None,
        None,
        None,
        false,
    );
    let short_seed =
        z_get_encryption_address(Some(secret(&[7; 31])), None, None, None, None, None, false);
    let short_key =
        z_get_encryption_address(None, Some(secret(&[0; 168])), None, None, None, None, false);
    let index_with_key = z_get_encryption_address(
        None,
        Some(secret(&[0; SPENDING_KEY_BYTES])),
        Some(0),
        None,
        None,
        None,
        false,
    );

    assert_eq!(invalid_input(neither), "seed or spendingKey is required");
    assert_eq!(
        invalid_input(both),
        "seed and spendingKey cannot both be set"
    );
    assert_eq!(invalid_input(short_seed), "seed must be 32 or 64 bytes");
    assert_eq!(
        invalid_input(short_key),
        "spendingKey must be exactly 169 bytes"
    );
    assert_eq!(
        invalid_input(index_with_key),
        "hdIndex can only be used with seed"
    );
}

#[test]
fn indices_and_ids_are_checked_before_deriving() {
    let big_index = z_get_encryption_address(
        Some(secret(&SEED)),
        None,
        None,
        Some(ZIP32_HARDENED_KEY_LIMIT),
        None,
        None,
        false,
    );
    let short_id = z_get_encryption_address(
        Some(secret(&SEED)),
        None,
        None,
        None,
        None,
        Some(&[1; 19]),
        false,
    );

    assert_eq!(
        invalid_input(big_index),
        "encryptionIndex must be an index between 0 and 2147483647"
    );
    assert_eq!(invalid_input(short_id), "toId must be exactly 20 bytes");
}

#[test]
fn encrypts_and_decrypts_with_the_ivk_and_with_the_ssk() {
    let keys = derive(None, None, false);
    let payload = encrypt_data(&keys.address.to_bytes(), secret(b"hello"), true).unwrap();
    let ssk = payload.symmetric_key.as_ref().expect("asked for");

    let with_ivk = decrypt_data(
        Some(secret(keys.ivk_bytes.expose_secret())),
        Some(&payload.ephemeral_public_key),
        secret(&payload.encrypted_data),
        None,
    )
    .unwrap();
    // epk is ignored with ssk, so a whole descriptor can be passed as it is.
    let with_ssk = decrypt_data(
        None,
        Some(&[0; 32]),
        secret(&payload.encrypted_data),
        Some(secret(ssk.expose_secret())),
    )
    .unwrap();

    assert_eq!(with_ivk.expose_secret().as_slice(), b"hello");
    assert_eq!(with_ssk.expose_secret().as_slice(), b"hello");
    assert_eq!(payload.encrypted_data.len(), b"hello".len() + TAG_BYTES);
}

#[test]
fn returns_the_ssk_only_when_asked() {
    let keys = derive(None, None, false);

    let payload = encrypt_data(&keys.address.to_bytes(), secret(b"hello"), false).unwrap();

    assert!(payload.symmetric_key.is_none());
}

#[test]
fn address_and_data_mistakes_are_invalid_input() {
    let address = derive(None, None, false).address.to_bytes();

    let short_address = encrypt_data(&address[..42], secret(b"hello"), false);
    let not_an_address = encrypt_data(&[0xff; 43], secret(b"hello"), false);
    let too_much_data = encrypt_data(&address, secret(&vec![0; MAX_PAYLOAD_BYTES + 1]), false);

    assert_eq!(
        invalid_input(short_address),
        "address must be exactly 43 bytes"
    );
    assert_eq!(
        invalid_input(not_an_address),
        "address is not a valid Sapling payment address"
    );
    assert_eq!(
        invalid_input(too_much_data),
        "data must be at most 1000000 bytes"
    );
}

#[test]
fn decryption_key_mistakes_are_invalid_input() {
    let ciphertext = || secret(&[0; TAG_BYTES]);
    let key = || Some(secret(&[0; 32]));

    let neither = decrypt_data(None, None, ciphertext(), None);
    let both = decrypt_data(key(), Some(&[0; 32]), ciphertext(), key());
    let ivk_without_epk = decrypt_data(key(), None, ciphertext(), None);
    let short_ivk = decrypt_data(Some(secret(&[0; 31])), Some(&[0; 32]), ciphertext(), None);
    let short_epk = decrypt_data(key(), Some(&[0; 31]), ciphertext(), None);
    let short_ssk = decrypt_data(None, None, ciphertext(), Some(secret(&[0; 31])));

    assert_eq!(invalid_input(neither), "ivk or ssk is required");
    assert_eq!(invalid_input(both), "ivk and ssk cannot both be set");
    assert_eq!(invalid_input(ivk_without_epk), "epk is required with ivk");
    assert_eq!(invalid_input(short_ivk), "ivk must be exactly 32 bytes");
    assert_eq!(invalid_input(short_epk), "epk must be exactly 32 bytes");
    assert_eq!(invalid_input(short_ssk), "ssk must be exactly 32 bytes");
}

#[test]
fn ciphertexts_of_impossible_sizes_are_invalid_input() {
    let too_short = decrypt_data(
        None,
        None,
        secret(&[0; TAG_BYTES - 1]),
        Some(secret(&[0; 32])),
    );
    let too_long = decrypt_data(
        None,
        None,
        secret(&vec![0; MAX_PAYLOAD_BYTES + TAG_BYTES + 1]),
        Some(secret(&[0; 32])),
    );

    assert_eq!(
        invalid_input(too_short),
        "encryptedData must be at least 16 bytes"
    );
    assert_eq!(
        invalid_input(too_long),
        "encryptedData must be at most 1000016 bytes"
    );
}

#[test]
fn a_wrong_key_or_a_changed_ciphertext_is_a_crypto_error() {
    let keys = derive(None, None, false);
    let payload = encrypt_data(&keys.address.to_bytes(), secret(b"hello"), true).unwrap();
    let ssk = payload
        .symmetric_key
        .as_ref()
        .unwrap()
        .expose_secret()
        .to_vec();

    let mut changed = payload.encrypted_data.clone();
    changed[0] ^= 1;
    let mut wrong_ssk = ssk.clone();
    wrong_ssk[0] ^= 1;
    let other_keys = derive(None, Some(1), false);

    let with_changed = decrypt_data(None, None, secret(&changed), Some(secret(&ssk)));
    let with_wrong_ssk = decrypt_data(
        None,
        None,
        secret(&payload.encrypted_data),
        Some(secret(&wrong_ssk)),
    );
    let with_other_ivk = decrypt_data(
        Some(secret(other_keys.ivk_bytes.expose_secret())),
        Some(&payload.ephemeral_public_key),
        secret(&payload.encrypted_data),
        None,
    );

    assert_eq!(crypto(with_changed), DECRYPTION_FAILED);
    assert_eq!(crypto(with_wrong_ssk), DECRYPTION_FAILED);
    assert_eq!(crypto(with_other_ivk), DECRYPTION_FAILED);
}

#[test]
fn errors_carry_their_kind_and_message() {
    let invalid = z_get_encryption_address(None, None, None, None, None, None, false)
        .err()
        .unwrap();
    let failed = decrypt_data(None, None, secret(&[0; TAG_BYTES]), Some(secret(&[0; 32])))
        .err()
        .unwrap();

    assert_eq!(invalid.kind(), "InvalidInput");
    assert_eq!(invalid.message(), "seed or spendingKey is required");
    assert_eq!(invalid.to_string(), "seed or spendingKey is required");
    assert_eq!(failed.kind(), "Crypto");
    assert_eq!(failed.message(), DECRYPTION_FAILED);
}

#[test]
fn fresh_salts_are_salt_sized_and_differ() {
    let first = fresh_salt().unwrap();
    let second = fresh_salt().unwrap();

    assert_eq!(first.len(), SALT_BYTES);
    assert_ne!(first, second);
}

#[test]
fn limits_are_the_values_the_checks_use() {
    assert_eq!(LIMITS.max_index, 2_147_483_647);
    assert_eq!(LIMITS.seed_lengths, [32, 64]);
    assert_eq!(LIMITS.spending_key_bytes, 169);
    assert_eq!(LIMITS.payment_address_bytes, 43);
    assert_eq!(LIMITS.identity_id_bytes, 20);
    assert_eq!(LIMITS.ivk_bytes, 32);
    assert_eq!(LIMITS.epk_bytes, 32);
    assert_eq!(LIMITS.ssk_bytes, 32);
    assert_eq!(LIMITS.tag_bytes, 16);
    assert_eq!(LIMITS.max_payload_bytes, 1_000_000);
    assert_eq!(LIMITS.salt_bytes, 32);
}
