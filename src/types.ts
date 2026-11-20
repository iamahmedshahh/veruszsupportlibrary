import {type DataDescriptor} from 'verus-typescript-primitives'

/*
 * The public types, the same on the web and on React Native. Bytes are
 * Uint8Arrays (a Buffer is one), and a result field that is not set is
 * undefined.
 */

/** "name@" (with `system`), an "i…" i-address, or the 20 bytes of a VerusID. */
export type IdentityInput = string | Uint8Array

/** The sizes and ranges the library checks, from veruszsupportcore's limits. */
export interface Limits {
  /** The largest hdIndex or encryptionIndex. */
  maxIndex: number
  seedLengths: number[]
  spendingKeyBytes: number
  paymentAddressBytes: number
  identityIdBytes: number
  ivkBytes: number
  epkBytes: number
  sskBytes: number
  tagBytes: number
  maxPayloadBytes: number
  saltBytes: number
}

export interface DerivationParams {
  /** 32 or 64 bytes. Give either seed or spendingKey. */
  seed?: Uint8Array | null
  spendingKey?: Uint8Array | null
  /** The account under a seed. Only with seed. */
  hdIndex?: number | null
  encryptionIndex?: number | null
  fromId?: IdentityInput | null
  toId?: IdentityInput | null
  /** The system a name@ in fromId or toId is on: 'VRSC' or 'VRSCTEST', in any case. */
  system?: string | null
  returnSecret?: boolean | null
}

export interface ChannelKeys {
  address: Uint8Array
  ivk: Uint8Array
  extfvk: Uint8Array
  /** Set only when returnSecret was true. */
  spendingKey: Uint8Array | undefined
}

export interface EncryptParams {
  address: Uint8Array
  data: Uint8Array
  returnSsk?: boolean | null
}

export interface EncryptedPayload {
  encryptedData: Uint8Array
  epk: Uint8Array
  /** Set only when returnSsk was true. */
  ssk: Uint8Array | undefined
}

/** Exactly one key: ivk (with epk) or ssk. epk is ignored with ssk. */
export interface DecryptParams {
  encryptedData: Uint8Array
  epk?: Uint8Array | null
  ivk?: Uint8Array | null
  ssk?: Uint8Array | null
}

export interface EncryptDescriptorParams {
  /** The data, with an optional mimeType, label and salt. */
  descriptor: DataDescriptor
  address: Uint8Array
  returnSsk?: boolean | null
}

export interface EncryptDescriptorResult {
  descriptor: DataDescriptor
  /** Set only when returnSsk was true. */
  ssk: Uint8Array | undefined
}

/** Exactly one key: ivk or ssk. */
export interface DecryptDescriptorParams {
  descriptor: DataDescriptor
  ivk?: Uint8Array | null
  ssk?: Uint8Array | null
}
