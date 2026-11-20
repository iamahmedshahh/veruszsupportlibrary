/*
 * The calls apps make.
 */
import {engine} from './engine'
import {checkSystem, resolveIdentity} from './identity'
import {
  type ChannelKeys,
  type DecryptParams,
  type DerivationParams,
  type EncryptedPayload,
  type EncryptParams,
  type Limits,
} from './types'
import {
  checkBytes,
  checkFlag,
  checkOptionalBytes,
  checkOptionalNumber,
} from './validate'

/** The sizes and ranges the library checks, from veruszsupportcore's limits. */
export function limits(): Limits {
  return engine.limits()
}

/**
 * Derives the Sapling channel keys used for encryption and decryption, as the
 * daemon's z_getencryptionaddress does.
 */
export async function zGetEncryptionAddress(
  params: DerivationParams,
): Promise<ChannelKeys> {
  const system = checkSystem(params.system)
  return engine.zGetEncryptionAddress({
    seed: checkOptionalBytes(params.seed, 'seed'),
    spendingKey: checkOptionalBytes(params.spendingKey, 'spendingKey'),
    hdIndex: checkOptionalNumber(params.hdIndex, 'hdIndex'),
    encryptionIndex: checkOptionalNumber(
      params.encryptionIndex,
      'encryptionIndex',
    ),
    fromId: resolveIdentity(params.fromId, system, 'fromId'),
    toId: resolveIdentity(params.toId, system, 'toId'),
    returnSecret: checkFlag(params.returnSecret, 'returnSecret'),
  })
}

/** Encrypts bytes to a Sapling payment address. */
export async function encryptData(
  params: EncryptParams,
): Promise<EncryptedPayload> {
  return engine.encryptData({
    address: checkBytes(params.address, 'address'),
    data: checkBytes(params.data, 'data'),
    returnSsk: checkFlag(params.returnSsk, 'returnSsk'),
  })
}

/** Decrypts bytes with exactly one key: ivk (with epk) or ssk. */
export async function decryptData(params: DecryptParams): Promise<Uint8Array> {
  return engine.decryptData({
    encryptedData: checkBytes(params.encryptedData, 'encryptedData'),
    epk: checkOptionalBytes(params.epk, 'epk'),
    ivk: checkOptionalBytes(params.ivk, 'ivk'),
    ssk: checkOptionalBytes(params.ssk, 'ssk'),
  })
}
