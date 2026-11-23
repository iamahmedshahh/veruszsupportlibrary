/** The two kinds of error, the same as veruszsupportcore's. */
export type VerusZSupportErrorKind = 'InvalidInput' | 'Crypto';
/**
 * The one error the library throws, on the web and on React Native alike.
 * The checks run in Rust, so both platforms give the same kinds and messages.
 *
 * - InvalidInput: the arguments were rejected before any cryptography ran.
 *   One is missing, extra, of the wrong type, length or range. The call must
 *   change to succeed.
 * - Crypto: the cryptography failed (a key that is not valid, the wrong key
 *   or the decrypted data is not a DataDescriptor.
 */
export declare class VerusZSupportError extends Error {
    readonly kind: VerusZSupportErrorKind;
    constructor(kind: VerusZSupportErrorKind, message: string, options?: ErrorOptions);
}
export declare function isVerusZSupportErrorKind(value: unknown): value is VerusZSupportErrorKind;
export declare function invalidInput(message: string): VerusZSupportError;
export declare function cryptoError(message: string): VerusZSupportError;
