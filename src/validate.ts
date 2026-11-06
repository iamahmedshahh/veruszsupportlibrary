/** ZIP-32 hardened index range: 0 ..= 2^31 - 1. Larger values make zip32 panic (WASM trap). */
const MAX_HARDENED_INDEX = 0x7fffffff;

/** Optional index: undefined/null → null; otherwise must be an integer in hardened range. */
export function assertIndex(v: unknown, field: string): number | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > MAX_HARDENED_INDEX) {
    throw new Error(`${field} must be an integer between 0 and ${MAX_HARDENED_INDEX}`);
  }
  return v;
}

/** Optional flag: undefined → false; otherwise must be a real boolean (no coercion). */
export function assertFlag(v: unknown, field: string): boolean {
  if (v === undefined) return false;
  if (typeof v !== 'boolean') throw new Error(`${field} must be a boolean`);
  return v;
}