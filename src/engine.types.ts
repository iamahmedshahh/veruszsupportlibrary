import {type ChannelKeys, type EncryptedPayload, type Limits} from './types'

/**
 * What each platform's engine runs in Rust: engine.ts on the web, and
 * engine.native.ts on React Native.
 *
 * The arguments are already type checked. Bytes are Uint8Arrays, a value not
 * given is undefined, and a failure is a VerusZSupportError. Both engines
 * answer at once, on the calling thread.
 */
export interface Engine {
  limits(): Limits
  freshSalt(): Uint8Array
  zGetEncryptionAddress(args: DerivationArgs): ChannelKeys
  encryptData(args: EncryptArgs): EncryptedPayload
  decryptData(args: DecryptArgs): Uint8Array
}

export interface DerivationArgs {
  seed: Uint8Array | undefined
  spendingKey: Uint8Array | undefined
  hdIndex: number | undefined
  encryptionIndex: number | undefined
  fromId: Uint8Array | undefined
  toId: Uint8Array | undefined
  returnSecret: boolean
}

export interface EncryptArgs {
  address: Uint8Array
  data: Uint8Array
  returnSsk: boolean
}

export interface DecryptArgs {
  encryptedData: Uint8Array
  epk: Uint8Array | undefined
  ivk: Uint8Array | undefined
  ssk: Uint8Array | undefined
}
