/**
 * Exports
 */

export { Sha224, Sha256 } from "@sha256/structs/sha256.struct";

/**
 * Imports
 */

import { Sha224, Sha256 } from "@sha256/structs/sha256.struct";

/**
 * Computes the SHA-256 digest of bytes.
 *
 * @param bytes - The bytes
 * @returns Their 32-byte digest
 *
 * @remarks
 * It's the SHA-256 of FIPS 180-4.
 * Use it when all the bytes are at hand, and {@link Sha256} when they arrive in pieces.
 *
 * @example
 * ```hx
 * const digest = sha256("abc");
 * let out: u8[64] = undefined;
 * try encodeHex(&digest, &out); // "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
 * ```
 *
 * @since 1.0.0
 */

export function sha256(bytes: readonly u8[]): u8[32] {
    let hash = Sha256.init();
    hash.update(bytes);

    return hash.finish();
}

/**
 * Computes the SHA-224 digest of bytes.
 *
 * @param bytes - The bytes
 * @returns Their 28-byte digest
 *
 * @remarks
 * It runs the rounds of SHA-256 from another initial state and keeps 28 bytes of the result.
 * Use it when all the bytes are at hand, and {@link Sha224} when they arrive in pieces.
 *
 * @example
 * ```hx
 * const digest = sha224("abc");
 * let out: u8[56] = undefined;
 * try encodeHex(&digest, &out); // "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
 * ```
 *
 * @since 1.0.0
 */

export function sha224(bytes: readonly u8[]): u8[28] {
    let hash = Sha224.init();
    hash.update(bytes);

    return hash.finish();
}
