/*
 * The web engine: the Rust code compiled to WebAssembly (veruszsupportweb).
 * Bundlers and Node pick this file; React Native picks engine.native.ts.
 */
import {
  decrypt_data,
  encrypt_data,
  fresh_salt,
  initSync,
  limits as wasmLimits,
  z_get_encryption_address,
} from 'veruszsupport'
import wasmUrl from 'veruszsupport/veruszsupport_bg.wasm?url'

import {type Engine} from './engine.types'
import {isVerusZSupportErrorKind, VerusZSupportError} from './errors'
import {type Limits} from './types'

let compiled = false

/**
 * Compiles the WebAssembly the first time it is needed. The build inlines it
 * as a data URL, so loading the library costs nothing and needs no fetch and
 * no top-level await.
 */
function load() {
  if (!compiled) {
    initSync({module: decodeDataUrl(wasmUrl)})
    compiled = true
  }
}

function decodeDataUrl(url: string): Uint8Array {
  const binary = atob(url.slice(url.indexOf(',') + 1))
  return Uint8Array.from(binary, char => char.charCodeAt(0))
}

/**
 * Runs a call into the WebAssembly. Rust throws an Error named after the kind
 * (to_js_error in veruszsupportweb), which becomes a VerusZSupportError.
 * Anything else, such as the trap a Rust panic causes, is thrown as it is.
 */
function call<T>(run: () => T): T {
  load()
  try {
    return run()
  } catch (error) {
    if (error instanceof Error && isVerusZSupportErrorKind(error.name)) {
      throw new VerusZSupportError(error.name, error.message)
    }
    throw error
  }
}

export const engine: Engine = {
  limits: () => call(() => wasmLimits() as Limits),

  freshSalt: () => call(() => fresh_salt()),

  zGetEncryptionAddress: args =>
    call(() => {
      const keys = z_get_encryption_address(
        args.seed,
        args.spendingKey,
        args.hdIndex,
        args.encryptionIndex,
        args.fromId,
        args.toId,
        args.returnSecret,
      )
      return {
        address: keys.address,
        ivk: keys.ivk,
        extfvk: keys.extfvk,
        spendingKey: keys.spendingKey,
      }
    }),

  encryptData: args =>
    call(() => {
      const payload = encrypt_data(args.address, args.data, args.returnSsk)
      return {
        encryptedData: payload.encryptedData,
        epk: payload.ephemeralPublicKey,
        ssk: payload.symmetricKey,
      }
    }),

  decryptData: args =>
    call(() => decrypt_data(args.ivk, args.epk, args.encryptedData, args.ssk)),
}
