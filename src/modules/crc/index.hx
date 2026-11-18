/**
 * Exports
 */

export { CRC32, CRC32BZip2, CRC64 } from "@crc/structs/crc.struct";

/**
 * Imports
 */

import { CRC32, CRC32BZip2, CRC64 } from "@crc/structs/crc.struct";

/**
 * Computes the CRC-32 of bytes.
 *
 * @param bytes - The bytes
 * @returns Their CRC-32, as zlib's `crc32` gives it
 *
 * @remarks
 * It's the CRC that gzip, PNG, zip, and xz store.
 * Use it when all the bytes are at hand, and {@link CRC32} when they arrive in pieces.
 *
 * @example
 * ```hx
 * crc32("123456789"); // 0xCBF43926
 * crc32("");          // 0
 * ```
 *
 * @since 1.0.0
 */

export function crc32(bytes: readonly u8[]): u32 {
    let check = CRC32.init();
    check.update(bytes);

    return check.finish();
}

/**
 * Computes the CRC-64 of bytes, as xz checks a block.
 *
 * @param bytes - The bytes
 * @returns Their CRC-64 in ECMA-182's reflected form
 *
 * @remarks
 * It's the CRC-64/XZ variant, which starts from all ones and inverts the result.
 * Use it when all the bytes are at hand, and {@link CRC64} when they arrive in pieces.
 *
 * @example
 * ```hx
 * crc64("123456789"); // 0x995DC9BBDF1939FA
 * crc64("");          // 0
 * ```
 *
 * @since 1.0.0
 */

export function crc64(bytes: readonly u8[]): u64 {
    let check = CRC64.init();
    check.update(bytes);

    return check.finish();
}

/**
 * Computes the CRC-32 of bytes, as bzip2 checks a block.
 *
 * @param bytes - The bytes
 * @returns Their CRC-32/BZIP2
 *
 * @remarks
 * It shares the polynomial of {@link crc32} but leaves the bits unreflected, so the two give different values.
 * Use it when all the bytes are at hand, and {@link CRC32BZip2} when they arrive in pieces.
 *
 * @example
 * ```hx
 * crc32BZip2("123456789"); // 0xFC891918
 * crc32BZip2("");          // 0
 * ```
 *
 * @since 1.0.0
 */

export function crc32BZip2(bytes: readonly u8[]): u32 {
    let check = CRC32BZip2.init();
    check.update(bytes);

    return check.finish();
}
