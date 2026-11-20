import {invalidInput} from './errors'

/*
 * Type checks for what TypeScript can't enforce at runtime, so a value of the
 * wrong type fails the same way on every platform instead of being coerced.
 * The values themselves (lengths, ranges, which keys go together) are checked
 * in Rust, with the limits.
 */

/** An optional flag: null and undefined are false, anything else must be a boolean. */
export function checkFlag(value: unknown, field: string): boolean {
  if (value == null) {
    return false
  }
  if (typeof value !== 'boolean') {
    throw invalidInput(`${field} must be a boolean`)
  }
  return value
}

export function checkBytes(value: unknown, field: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw invalidInput(`${field} must be a Uint8Array`)
  }
  return value
}

/** Optional bytes: null and undefined both mean not given. */
export function checkOptionalBytes(
  value: unknown,
  field: string,
): Uint8Array | undefined {
  return value == null ? undefined : checkBytes(value, field)
}

/** An optional number: null and undefined both mean not given. */
export function checkOptionalNumber(
  value: unknown,
  field: string,
): number | undefined {
  if (value == null) {
    return undefined
  }
  if (typeof value !== 'number') {
    throw invalidInput(`${field} must be a number`)
  }
  return value
}
