/** Optional index: undefined/null → null; otherwise must be an integer in hardened range. */
export declare function assertIndex(v: unknown, field: string): number | null;
/** Optional flag: undefined → false; otherwise must be a real boolean (no coercion). */
export declare function assertFlag(v: unknown, field: string): boolean;
