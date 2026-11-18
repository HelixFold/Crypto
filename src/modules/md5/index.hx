/**
 * Exports
 */

export { Md5 } from "@md5/structs/md5.struct";

/**
 * Imports
 */

import { Md5 } from "@md5/structs/md5.struct";

/**
 * Computes the MD5 digest of bytes, for legacy formats only.
 *
 * @param bytes - The bytes
 * @returns Their 16-byte digest
 *
 * @remarks
 * MD5 is broken for security, since anyone can make two inputs with the same digest in seconds.
 * Use it only where a format fixes it, such as an old checksum file, and never to protect data from an attacker.
 * Use it when all the bytes are at hand, and {@link Md5} when they arrive in pieces.
 *
 * @example
 * ```hx
 * const digest = md5("abc");
 * let out: u8[32] = undefined;
 * try encodeHex(&digest, &out); // "900150983cd24fb0d6963f7d28e17f72"
 * ```
 *
 * @since 1.0.0
 */

export function md5(bytes: readonly u8[]): u8[16] {
    let hash = Md5.init();
    hash.update(bytes);

    return hash.finish();
}
