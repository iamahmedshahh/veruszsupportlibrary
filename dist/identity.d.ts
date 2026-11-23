import { type IdentityInput } from './types';
/**
 * Checks system: VRSC or VRSCTEST, in any case. A misspelled system would
 * still resolve a name@, to an ID on no chain, so anything else is refused.
 * Null and undefined mean not given.
 */
export declare function checkSystem(value: unknown): string | undefined;
/**
 * Resolves fromId or toId to the 20 bytes of a VerusID. Bytes pass through as
 * they are: Rust checks their length with the other inputs.
 */
export declare function resolveIdentity(id: IdentityInput | null | undefined, system: string | undefined, field: string): Uint8Array | undefined;
