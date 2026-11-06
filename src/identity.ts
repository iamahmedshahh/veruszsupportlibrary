import { fromBase58Check, toIAddress } from 'verus-typescript-primitives';

/** Version byte of a Verus identity (i-) address. Rejects R-addresses. */
const I_ADDRESS_VERSION = 102;

/** "name@", "i…" i-address, or 20 raw bytes. */
export type IdentityInput = string | Uint8Array;

export function resolveIdentity(id: IdentityInput, system: string = 'VRSC', field: string) : Uint8Array {
  // already resolved by the caller — use as-is
  if (id instanceof Uint8Array) {
    if (id.length !== 20) throw new Error(`${field} must be exactly 20 bytes`);
    return id;
  }

  let iAddress = id;
  if (id.endsWith('@')) {
    // names are chain-scoped: mike@ on VRSC and on VRSCTEST are different IDs
    iAddress = toIAddress(id.slice(0, -1), system);
  }

  let decoded;
  try {
    decoded = fromBase58Check(iAddress);
  } catch {
    throw new Error(`${field} is not a valid i-address or name@`);
  }
  if (decoded.version !== I_ADDRESS_VERSION) throw new Error(`${field} is not an identity (i-) address`);
  return new Uint8Array(decoded.hash);
}