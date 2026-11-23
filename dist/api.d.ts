import { type ChannelKeys, type DecryptParams, type DerivationParams, type EncryptedPayload, type EncryptParams, type Limits } from './types';
/** The sizes and ranges the library checks, from veruszsupportcore's limits. */
export declare function limits(): Limits;
/**
 * Derives the Sapling channel keys used for encryption and decryption, as the
 * daemon's z_getencryptionaddress does.
 */
export declare function zGetEncryptionAddress(params: DerivationParams): Promise<ChannelKeys>;
/** Encrypts bytes to a Sapling payment address. */
export declare function encryptData(params: EncryptParams): Promise<EncryptedPayload>;
/** Decrypts bytes with exactly one key: ivk (with epk) or ssk. */
export declare function decryptData(params: DecryptParams): Promise<Uint8Array>;
