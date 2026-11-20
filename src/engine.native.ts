/*
 * The React Native engine: the Rust code compiled for Android and iOS, in
 * @veruszsupportlib/react-native-veruszsupport. Metro picks this file over
 * engine.ts on native.
 */
import * as native from '@veruszsupportlib/react-native-veruszsupport'

import {type Engine} from './engine.types'
import {isVerusZSupportErrorKind, VerusZSupportError} from './errors'

/**
 * uniffi takes bytes only as ArrayBuffers. Copies exactly the bytes of the
 * view, since a Buffer is often a slice of a larger, shared one.
 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer
function toArrayBuffer(bytes: Uint8Array | undefined): ArrayBuffer | undefined
function toArrayBuffer(bytes: Uint8Array | undefined): ArrayBuffer | undefined {
  return bytes === undefined ? undefined : Uint8Array.from(bytes).buffer
}

/** Zeroes the copies of secrets made for a call only on native, once Rust has its own */
function wipe(...buffers: Array<ArrayBuffer | undefined>) {
  for (const buffer of buffers) {
    if (buffer) {
      new Uint8Array(buffer).fill(0)
    }
  }
}

/**
 * uniffi's error keeps its message in inner.message. It is thrown again as
 * the library's own error, the same one the web engine throws.
 */
function toLibraryError(error: unknown): unknown {
  if (
    native.VerusZSupportError.instanceOf(error) &&
    isVerusZSupportErrorKind(error.tag)
  ) {
    return new VerusZSupportError(error.tag, error.inner.message, {
      cause: error,
    })
  }
  return error
}

/** Runs a call into the native bindings, rethrowing uniffi's error as the library's. */
function call<T>(run: () => T): T {
  try {
    return run()
  } catch (error) {
    throw toLibraryError(error)
  }
}

export const engine: Engine = {
  limits: () => native.limits(),

  freshSalt: () => new Uint8Array(call(() => native.freshSalt())),

  zGetEncryptionAddress: args => {
    const seed = toArrayBuffer(args.seed)
    const spendingKey = toArrayBuffer(args.spendingKey)
    try {
      const keys = call(() =>
        native.zGetEncryptionAddress(
          seed,
          spendingKey,
          args.hdIndex,
          args.encryptionIndex,
          toArrayBuffer(args.fromId),
          toArrayBuffer(args.toId),
          args.returnSecret,
        ),
      )
      return {
        address: new Uint8Array(keys.address),
        ivk: new Uint8Array(keys.ivk),
        extfvk: new Uint8Array(keys.extfvk),
        spendingKey: keys.spendingKey && new Uint8Array(keys.spendingKey),
      }
    } finally {
      wipe(seed, spendingKey)
    }
  },

  encryptData: args => {
    const data = toArrayBuffer(args.data)
    try {
      const payload = call(() =>
        native.encryptData(toArrayBuffer(args.address), data, args.returnSsk),
      )
      return {
        encryptedData: new Uint8Array(payload.encryptedData),
        epk: new Uint8Array(payload.ephemeralPublicKey),
        ssk: payload.symmetricKey && new Uint8Array(payload.symmetricKey),
      }
    } finally {
      wipe(data)
    }
  },

  decryptData: args => {
    const ivk = toArrayBuffer(args.ivk)
    const ssk = toArrayBuffer(args.ssk)
    try {
      const decrypted = call(() =>
        native.decryptData(
          ivk,
          toArrayBuffer(args.epk),
          toArrayBuffer(args.encryptedData),
          ssk,
        ),
      )
      return new Uint8Array(decrypted)
    } finally {
      wipe(ivk, ssk)
    }
  },
}
