import {
  z_get_encryptionaddress,
  encrypt_v_data,
  decrypt_v_data,
} from 'veruszsupport';

import { DataDescriptor } from 'verus-typescript-primitives';
import { assertIndex, assertFlag } from './validate';
import { useThenWipe } from './memory';
import { VdxfUniValue } from 'verus-typescript-primitives';
import { DataDescriptorKey } from 'verus-typescript-primitives';
import { BN } from 'bn.js';
import { Buffer } from 'buffer';
import { resolveIdentity, type IdentityInput } from './identity';

export { DataDescriptor, VdxfUniValue, DataDescriptorKey };


export interface DerivationParams {
  seed?:            Uint8Array;
  spendingKey?:     Uint8Array;
  hdIndex?:         number;
  encryptionIndex?: number;
  fromId?:          IdentityInput;
  toId?:            IdentityInput;
  system?:          string;
  returnSecret?:    boolean;
}

export interface ChannelKeys {
  address:     Uint8Array;
  ivk:         Uint8Array;
  extfvk:      Uint8Array;
  spendingKey: Uint8Array | null;
}

export interface EncryptParams {
  address:    Uint8Array;
  data:       Uint8Array;
  returnSsk?: boolean;
}

export interface EncryptedPayload {
  ephemeralPublicKey: Uint8Array;
  objectdata:         Uint8Array;
  symmetricKey:       Uint8Array | null;
}

export interface EncryptedDescriptor {
  objectdata: Uint8Array;
  epk?:       Uint8Array | null;
  ivk?:       Uint8Array | null;
  ssk?:       Uint8Array | null;
}


/**
 * Derives Sapling channel keys for encryption/decryption.
 */
export function z_getEncryptionAddress(params: DerivationParams): ChannelKeys {

  const hdIndex         = assertIndex(params.hdIndex, 'hdIndex');
  const encryptionIndex = assertIndex(params.encryptionIndex, 'encryptionIndex');
  const returnSecret    = assertFlag(params.returnSecret, 'returnSecret');

  const result = z_get_encryptionaddress(
    params.seed            ?? null,
    params.spendingKey     ?? null,
    hdIndex,
    encryptionIndex,
    params.fromId != null ? resolveIdentity(params.fromId, params.system, 'fromId') : null,
    params.toId   != null ? resolveIdentity(params.toId,   params.system, 'toId')   : null,
    returnSecret,
  );

  return {
    address:     result.address,
    ivk:         result.ivk,
    extfvk:      result.extfvk,
    spendingKey: result.spendingKey ?? null,
  };
}


// Encrypt and decrypt raw bytes, without flags or salt from Core Rust

export function encryptData(params: EncryptParams): EncryptedPayload {

  const returnSsk = assertFlag(params.returnSsk, 'returnSsk')

  const result = encrypt_v_data(
    params.address,
    params.data,
    returnSsk ,
  );

  return {
    ephemeralPublicKey: result.ephemeralPublicKey,
    objectdata:         result.encryptedData,
    symmetricKey:       result.symmetricKey ?? null,
  };
}

export function decryptData(descriptor: EncryptedDescriptor): Uint8Array {
  const ivk = descriptor.ivk ?? null;
  const epk = descriptor.epk ?? null;
  const ssk = descriptor.ssk ?? null;

    if (ivk && ssk) throw new Error('descriptor has both ivk and ssk — provide only one');

        if (ivk) {
          if (!epk) throw new Error('descriptor has ivk but no epk');
          return decrypt_v_data(ivk, epk, descriptor.objectdata, null);
        }
        if (ssk) return decrypt_v_data(null, null, descriptor.objectdata, ssk);

        throw new Error('descriptor has no decryption key — needs ivk or ssk');
  }



// Wraps the plaintext as a VdxfUniValue containing a DataDescriptor entry —

export interface EncryptDescriptorParams {
  descriptor: DataDescriptor;   
  address:    Uint8Array;       
  returnSsk?: boolean;
}

export interface EncryptDescriptorResult {
  descriptor: DataDescriptor;   
  ssk:        Uint8Array | null;
}

export interface DecryptDescriptorParams {
  descriptor: DataDescriptor;   
  ivk?:       Uint8Array;
  ssk?:       Uint8Array;
}


function randomBytes32(): Buffer {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is not available in this environment');
  }
  const arr = new Uint8Array(32);
  c.getRandomValues(arr);
  return Buffer.from(arr);
}

// Encrypts a DataDescriptor to a Sapling address in daemon-compatible format.

export function encryptDescriptor(params: EncryptDescriptorParams): EncryptDescriptorResult {

  const input = params.descriptor;

  // Reject empty input 
  if (!input.objectdata || input.objectdata.length === 0) {
    throw new Error('encryptDescriptor: input descriptor has no objectdata');
  }


  const innerSalt = input.salt && input.salt.length === 32
    ? input.salt
    : randomBytes32();

  // Build the DataDescriptor that will be encrypted.

  const innerDescriptor = new DataDescriptor({
    version:    new BN(1),
    objectdata: input.objectdata,
    salt:       innerSalt,
    label:      input.label,
    mimeType:   input.mimeType,
  });

  // The daemon expects the encrypted plaintext to start with a 20-byte VDXF
  // key prefix 

  const wrapped = new VdxfUniValue({
    values: [
      { [DataDescriptorKey.vdxfid]: innerDescriptor }
    ]
  });

  // Serialize the wrapped structure to raw bytes — these bytes are what actually go into the encryption function.

  const plaintext = wrapped.toBuffer();

  const result = useThenWipe(plaintext, (bytes) =>   encryptData({
    address:   params.address,
    data:      bytes,
    returnSsk: params.returnSsk ?? false,
  }));

  // Build the descriptor that gets returned to the caller. 

  const outerDescriptor = new DataDescriptor({
    version:    new BN(1),
    flags:      DataDescriptor.FLAG_ENCRYPTED_DATA,
    objectdata: Buffer.from(result.objectdata),
    epk:        Buffer.from(result.ephemeralPublicKey),
  });

  // Return the encrypted descriptor and the symmetric key or null if returnSsk was false. 
  return {
    descriptor: outerDescriptor,
    ssk:        result.symmetricKey,
  };
}


// Decrypts an encrypted DataDescriptor and returns the original one.

export function decryptDescriptor(params: DecryptDescriptorParams): DataDescriptor {

  // Pull out the three things we need: the encrypted descriptor and either
  // an ivk (incoming viewing key) or ssk (symmetric session key) to decrypt with.
  const { descriptor, ivk, ssk } = params;

  // Reject empty objectdata — nothing to decrypt means malformed input
  if (!descriptor.objectdata || descriptor.objectdata.length === 0) {
    throw new Error('decryptDescriptor: encrypted descriptor has no objectdata');
  }

  // Run the actual decryption. Path depends on which key was supplied:
  // Returns the raw bytes of the wrapped plaintext.

  const decrypted = decryptData({
    objectdata: new Uint8Array(descriptor.objectdata),
    epk:        descriptor.epk ? new Uint8Array(descriptor.epk) : null,
    ivk:        ivk ?? null,
    ssk:        ssk ?? null,
  });

  // The plaintext is in the daemon's wrapped format:
  //   [20-byte VDXF key] [version] [length] [serialized DataDescriptor]
  // Use VdxfUniValue.fromBuffer to parse it back into structured values.

  const plainView = Buffer.from(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);

  // decrypted bytes are untrusted input: anyone can encrypt to a public address
  const vdxfValue = new VdxfUniValue();
  try {
    vdxfValue.fromBuffer(plainView, 0);
  } catch {
    decrypted.fill(0);
    throw new Error('decryptDescriptor: decrypted plaintext is malformed');
  }
  // Walk the values array looking for the entry keyed by DataDescriptorKey —
  // that's where the original descriptor lives. The wrapper structure could
  // theoretically hold other entries, but for encryption we only put one in.
  for (const inner of vdxfValue.values) {
    const key = Object.keys(inner)[0];
    const found = inner[key];
      // input must actually be a DataDescriptor
      if (!(found instanceof DataDescriptor)) break;
      return found;
  }
  decrypted.fill(0);
  throw new Error('decryptDescriptor: decrypted plaintext does not contain a DataDescriptor');
}