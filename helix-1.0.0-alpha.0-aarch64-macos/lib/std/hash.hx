/**
 * The CRC-32 lookup table (polynomial 0xEDB88320, reflected), filled on the first call to {@link crc32}.
 *
 * @remarks
 * Filling it twice, say from two threads at once, writes the same values, so the lazy start is harmless.
 *
 * @since 1.0.0
 */

let crc32Table: u32[256] = undefined;
let crc32Ready: bool = false;

/**
 * The CRC-64 lookup table (ECMA-182, polynomial 0xC96C5795D7870F42, reflected), filled on the first call to
 * {@link crc64}.
 *
 * @since 1.0.0
 */

let crc64Table: u64[256] = undefined;
let crc64Ready: bool = false;

/**
 * Continues a CRC-32 over more bytes.
 *
 * @param crc - The CRC of the bytes before, or 0 to start
 * @param bytes - The next bytes
 * @returns The CRC of everything so far
 *
 * @remarks
 * It is the CRC-32 of gzip, zip, PNG, xz, and Ethernet (ISO-HDLC), so the result compares directly with the value
 * that those formats store.
 * Feeding the bytes in pieces gives the same result as feeding them at once.
 *
 * @example
 * ```hx
 * crc32(0, "123456789"); // 0xCBF43926
 * crc32(crc32(0, "1234"), "56789"); // 0xCBF43926
 * ```
 *
 * @since 1.0.0
 */

export function crc32(crc: u32, bytes: readonly u8[]): u32 {
    if (!crc32Ready) {
        for (const i of 0..256) {
            let c = i as u32;
            for (const _ of 0..8) c = (c & 1) != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1;
            crc32Table[i] = c;
        }
        crc32Ready = true;
    }
    let c = ~crc;
    for (const b of bytes) c = crc32Table[((c ^ b) & 0xFF) as usize] ^ (c >> 8);
    return ~c;
}

/**
 * Continues a CRC-64 over more bytes.
 *
 * @param crc - The CRC of the bytes before, or 0 to start
 * @param bytes - The next bytes
 * @returns The CRC of everything so far
 *
 * @remarks
 * It is the CRC-64 of xz (CRC-64/XZ, ECMA-182 reflected).
 *
 * @example
 * ```hx
 * crc64(0, "123456789"); // 0x995DC9BBDF1939FA
 * ```
 *
 * @since 1.0.0
 */

export function crc64(crc: u64, bytes: readonly u8[]): u64 {
    if (!crc64Ready) {
        for (const i of 0..256) {
            let c = i as u64;
            for (const _ of 0..8) c = (c & 1) != 0 ? 0xC96C_5795_D787_0F42 ^ (c >> 1) : c >> 1;
            crc64Table[i] = c;
        }
        crc64Ready = true;
    }
    let c = ~crc;
    for (const b of bytes) c = crc64Table[((c ^ b) & 0xFF) as usize] ^ (c >> 8);
    return ~c;
}
