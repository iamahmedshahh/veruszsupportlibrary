/*
 * veruszsupportlib: Sapling encryption and key derivation for Verus apps.
 *
 * One API for the web and React Native. Only ./engine differs between them:
 * engine.ts runs the Rust as WebAssembly, engine.native.ts as native code.
 */
export {decryptData, encryptData, limits, zGetEncryptionAddress} from './api'
export {decryptDescriptor, encryptDescriptor} from './descriptor'
export {VerusZSupportError, type VerusZSupportErrorKind} from './errors'
export type {
  ChannelKeys,
  DecryptDescriptorParams,
  DecryptParams,
  DerivationParams,
  EncryptDescriptorParams,
  EncryptDescriptorResult,
  EncryptedPayload,
  EncryptParams,
  IdentityInput,
  Limits,
} from './types'
export {
  DataDescriptor,
  DataDescriptorKey,
  VdxfUniValue,
} from 'verus-typescript-primitives'
