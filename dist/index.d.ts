import { DataDescriptor } from 'verus-typescript-primitives';
import { VdxfUniValue } from 'verus-typescript-primitives';
import { DataDescriptorKey } from 'verus-typescript-primitives';
import { type IdentityInput } from './identity';
export { DataDescriptor, VdxfUniValue, DataDescriptorKey };
export interface DerivationParams {
    seed?: Uint8Array;
    spendingKey?: Uint8Array;
    hdIndex?: number;
    encryptionIndex?: number;
    fromId?: IdentityInput;
    toId?: IdentityInput;
    system?: string;
    returnSecret?: boolean;
}
export interface ChannelKeys {
    address: Uint8Array;
    ivk: Uint8Array;
    extfvk: Uint8Array;
    spendingKey: Uint8Array | null;
}
export interface EncryptParams {
    address: Uint8Array;
    data: Uint8Array;
    returnSsk?: boolean;
}
export interface EncryptedPayload {
    ephemeralPublicKey: Uint8Array;
    objectdata: Uint8Array;
    symmetricKey: Uint8Array | null;
}
export interface EncryptedDescriptor {
    objectdata: Uint8Array;
    epk?: Uint8Array | null;
    ivk?: Uint8Array | null;
    ssk?: Uint8Array | null;
}
/**
 * Derives Sapling channel keys for encryption/decryption.
 */
export declare function z_getEncryptionAddress(params: DerivationParams): ChannelKeys;
export declare function encryptData(params: EncryptParams): EncryptedPayload;
export declare function decryptData(descriptor: EncryptedDescriptor): Uint8Array;
export interface EncryptDescriptorParams {
    descriptor: DataDescriptor;
    address: Uint8Array;
    returnSsk?: boolean;
}
export interface EncryptDescriptorResult {
    descriptor: DataDescriptor;
    ssk: Uint8Array | null;
}
export interface DecryptDescriptorParams {
    descriptor: DataDescriptor;
    ivk?: Uint8Array;
    ssk?: Uint8Array;
}
export declare function encryptDescriptor(params: EncryptDescriptorParams): EncryptDescriptorResult;
export declare function decryptDescriptor(params: DecryptDescriptorParams): DataDescriptor;
