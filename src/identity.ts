import {
  fromBase58Check,
  I_ADDR_VERSION,
  toIAddress,
} from 'verus-typescript-primitives'

import {invalidInput} from './errors'
import {type IdentityInput} from './types'

const SYSTEMS = ['VRSC', 'VRSCTEST']

/**
 * Checks system: VRSC or VRSCTEST, in any case. A misspelled system would
 * still resolve a name@, to an ID on no chain, so anything else is refused.
 * Null and undefined mean not given.
 */
export function checkSystem(value: unknown): string | undefined {
  if (value == null) {
    return undefined
  }
  if (typeof value !== 'string' || !SYSTEMS.includes(value.toUpperCase())) {
    throw invalidInput('system must be VRSC or VRSCTEST')
  }
  return value.toUpperCase()
}

/**
 * Resolves fromId or toId to the 20 bytes of a VerusID. Bytes pass through as
 * they are: Rust checks their length with the other inputs.
 */
export function resolveIdentity(
  id: IdentityInput | null | undefined,
  system: string | undefined,
  field: string,
): Uint8Array | undefined {
  if (id == null) {
    return undefined
  }
  if (id instanceof Uint8Array) {
    return id
  }
  if (typeof id !== 'string') {
    throw invalidInput(`${field} must be a name@, an i-address or a Uint8Array`)
  }

  const isName = id.endsWith('@')
  if (isName && !system) {
    throw invalidInput(`system is required when ${field} is a name@`)
  }

  let decoded
  try {
    decoded = fromBase58Check(isName ? toIAddress(id.slice(0, -1), system) : id)
  } catch {
    throw invalidInput(`${field} is not a valid i-address or name@`)
  }
  if (decoded.version !== I_ADDR_VERSION) {
    throw invalidInput(`${field} is not an identity (i-) address`)
  }
  return new Uint8Array(decoded.hash)
}
