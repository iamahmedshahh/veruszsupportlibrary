/** "name@", "i…" i-address, or 20 raw bytes. */
export type IdentityInput = string | Uint8Array;
export declare function resolveIdentity(id: IdentityInput, system: string | undefined, field: string): Uint8Array;
