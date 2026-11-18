/**
 * Exports
 */

export { Adler32 } from "@adler32/structs/adler32.struct";

/**
 * Imports
 */

import { Adler32 } from "@adler32/structs/adler32.struct";

/**
 * Computes the Adler-32 checksum of bytes.
 *
 * @param bytes - The bytes
 * @returns Their Adler-32, as zlib's `adler32` gives it
 *
 * @remarks
 * It's the checksum at the end of every zlib stream, faster than CRC-32 but weaker on short inputs.
 * Use it when all the bytes are at hand, and {@link Adler32} when they arrive in pieces.
 * It catches accidental damage only and is not for security,
 * since anyone who changes the bytes can recompute it.
 *
 * @example
 * ```hx
 * adler32("Wikipedia"); // 0x11E60398
 * adler32("");          // 1
 * ```
 *
 * @since 1.0.0
 */

export function adler32(bytes: readonly u8[]): u32 {
    let check = Adler32.init();
    check.update(bytes);

    return check.finish();
}
