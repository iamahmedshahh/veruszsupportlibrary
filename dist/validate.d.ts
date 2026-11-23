/** An optional flag: null and undefined are false, anything else must be a boolean. */
export declare function checkFlag(value: unknown, field: string): boolean;
export declare function checkBytes(value: unknown, field: string): Uint8Array;
/** Optional bytes: null and undefined both mean not given. */
export declare function checkOptionalBytes(value: unknown, field: string): Uint8Array | undefined;
/** An optional number: null and undefined both mean not given. */
export declare function checkOptionalNumber(value: unknown, field: string): number | undefined;
