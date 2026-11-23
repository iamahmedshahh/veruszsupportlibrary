import { DataDescriptor } from 'verus-typescript-primitives';
import { type DecryptDescriptorParams, type EncryptDescriptorParams, type EncryptDescriptorResult } from './types';
/**
 * Encrypts a DataDescriptor to a Sapling address the way the daemon does, so
 * the daemon's decryptdata opens the result.
 */
export declare function encryptDescriptor(params: EncryptDescriptorParams): Promise<EncryptDescriptorResult>;
/** Decrypts an encrypted DataDescriptor and returns the descriptor inside. */
export declare function decryptDescriptor(params: DecryptDescriptorParams): Promise<DataDescriptor>;
