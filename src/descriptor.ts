import {Buffer} from 'buffer'
import {
  DataDescriptor,
  DataDescriptorKey,
  VdxfUniValue,
} from 'verus-typescript-primitives'

import {decryptData, encryptData, limits} from './api'
import {engine} from './engine'
import {cryptoError, invalidInput} from './errors'
import {
  type DecryptDescriptorParams,
  type EncryptDescriptorParams,
  type EncryptDescriptorResult,
} from './types'

/**
 * Encrypts a DataDescriptor to a Sapling address the way the daemon does, so
 * the daemon's decryptdata opens the result.
 */
export async function encryptDescriptor(
  params: EncryptDescriptorParams,
): Promise<EncryptDescriptorResult> {
  const {descriptor} = params
  if (!descriptor?.objectdata?.length) {
    throw invalidInput('descriptor has no objectdata')
  }

  // A salt the caller set is used as it is, so it must be the daemon's size.
  // Without one, Rust makes a fresh one

  const {saltBytes} = limits()
  const salt = descriptor.salt?.length
    ? descriptor.salt
    : Buffer.from(engine.freshSalt())
  if (salt.length !== saltBytes) {
    throw invalidInput(`salt must be exactly ${saltBytes} bytes`)
  }

  // The daemon wraps the descriptor in a VDXF value keyed by DataDescriptorKey
  // before it encrypts
  const plaintext = new VdxfUniValue({
    values: [
      {
        [DataDescriptorKey.vdxfid]: new DataDescriptor({
          objectdata: descriptor.objectdata,
          salt,
          label: descriptor.label,
          mimeType: descriptor.mimeType,
        }),
      },
    ],
  }).toBuffer()

  try {
    const payload = await encryptData({
      address: params.address,
      data: plaintext,
      returnSsk: params.returnSsk,
    })
    return {
      descriptor: new DataDescriptor({
        flags: DataDescriptor.FLAG_ENCRYPTED_DATA,
        objectdata: Buffer.from(payload.encryptedData),
        epk: Buffer.from(payload.epk),
      }),
      ssk: payload.ssk,
    }
  } finally {
    plaintext.fill(0)
  }
}

/** Decrypts an encrypted DataDescriptor and returns the descriptor inside. */
export async function decryptDescriptor(
  params: DecryptDescriptorParams,
): Promise<DataDescriptor> {
  const {descriptor, ivk, ssk} = params
  if (!descriptor?.objectdata?.length) {
    throw invalidInput('descriptor has no objectdata')
  }

  const plaintext = await decryptData({
    encryptedData: descriptor.objectdata,
    epk: descriptor.epk,
    ivk,
    ssk,
  })

  // The plaintext is the daemon's wrapper. Anyone can encrypt to an address,
  // so it is untrusted until it parses.
  const bytes = Buffer.from(plaintext)
  plaintext.fill(0)

  const wrapper = new VdxfUniValue()
  try {
    wrapper.fromBuffer(Buffer.from(bytes), 0)
  } catch {
    plaintext.fill(0)
    throw cryptoError('decrypted data is malformed')
  }

  // The descriptor is the entry under DataDescriptorKey, where the daemon
  // puts it.
  const found = wrapper.values
    .map(value => value[DataDescriptorKey.vdxfid])
    .find((value): value is DataDescriptor => value instanceof DataDescriptor)
  if (!found) {
    plaintext.fill(0)
    throw cryptoError('decrypted data has no DataDescriptor')
  }
  return found
}
