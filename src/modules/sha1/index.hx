/**
 * Exports
 */

export { Sha1 } from "@sha1/structs/sha1.struct";

/**
 * Imports
 */

import { Sha1 } from "@sha1/structs/sha1.struct";

/**
 * Computes the SHA-1 digest of bytes, for legacy formats only.
 *
 * @param bytes - The bytes
 * @returns Their 20-byte digest
 *
 * @remarks
 * SHA-1 is broken for security, since anyone can make two inputs with the same digest.
 * Use it only where a format fixes it, such as the ids of git objects, and never to protect data from an attacker.
 * Use it when all the bytes are at hand, and {@link Sha1} when they arrive in pieces.
 *
 * @example
 * ```hx
 * const digest = sha1("abc");
 * let out: u8[40] = undefined;
 * try encodeHex(&digest, &out); // "a9993e364706816aba3e25717850c26c9cd0d89d"
 * ```
 *
 * @since 1.0.0
 */

export function sha1(bytes: readonly u8[]): u8[20] {
    let hash = Sha1.init();
    hash.update(bytes);

    return hash.finish();
}
