/**
 * Exports
 */

export { Sha384, Sha512 } from "@sha512/structs/sha512.struct";

/**
 * Imports
 */

import { Sha384, Sha512 } from "@sha512/structs/sha512.struct";

/**
 * Computes the SHA-512 digest of bytes.
 *
 * @param bytes - The bytes
 * @returns Their 64-byte digest
 *
 * @remarks
 * It's the SHA-512 of FIPS 180-4.
 * Use it when all the bytes are at hand, and {@link Sha512} when they arrive in pieces.
 *
 * @example
 * ```hx
 * const digest = sha512("abc");
 * let out: u8[128] = undefined;
 * try encodeHex(&digest, &out); // "ddaf35a193617aba...2a9ac94fa54ca49f"
 * ```
 *
 * @since 1.0.0
 */

export function sha512(bytes: readonly u8[]): u8[64] {
    let hash = Sha512.init();
    hash.update(bytes);

    return hash.finish();
}

/**
 * Computes the SHA-384 digest of bytes.
 *
 * @param bytes - The bytes
 * @returns Their 48-byte digest
 *
 * @remarks
 * It runs the rounds of SHA-512 from another initial state and keeps 48 bytes of the result.
 * Use it when all the bytes are at hand, and {@link Sha384} when they arrive in pieces.
 *
 * @example
 * ```hx
 * const digest = sha384("abc");
 * let out: u8[96] = undefined;
 * try encodeHex(&digest, &out); // "cb00753f45a35e8b...a1e7cc2358baeca134c825a7"
 * ```
 *
 * @since 1.0.0
 */

export function sha384(bytes: readonly u8[]): u8[48] {
    let hash = Sha384.init();
    hash.update(bytes);

    return hash.finish();
}
