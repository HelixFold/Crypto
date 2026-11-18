/**
 * Exports
 */

export { HexError } from "@hex/errors/hex.error";

/**
 * Imports
 */

import { HexError } from "@hex/errors/hex.error";

/**
 * The lowercase hex digits, indexed by their value.
 *
 * @remarks
 * Encoding always writes lowercase, which is how digests are usually printed and compared.
 *
 * @since 1.0.0
 */

const Digits = "0123456789abcdef";

/**
 * Reads the value of one hex digit.
 *
 * @param c - The character
 * @returns Its value, from 0 to 15
 * @throws HexError.BadDigit for anything but `0-9`, `a-f`, or `A-F`
 *
 * @remarks
 * It accepts both cases, so text from any encoder decodes.
 *
 * @since 1.0.0
 */

function digit(c: u8): u8 | Error {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw HexError.BadDigit;
}

/**
 * Writes bytes as lowercase hex.
 *
 * @param bytes - The bytes
 * @param out - The buffer for the digits, at least twice as long as `bytes`
 * @returns The part of `out` that holds the digits
 * @throws HexError.ShortBuffer when `out` is too small
 *
 * @remarks
 * Each byte becomes two digits, high nibble first.
 * It writes into `out` and allocates nothing, so it works without an allocator.
 *
 * @example
 * ```hx
 * let out: u8[6] = undefined;
 * try encodeHex("\x00\xff\x10", &out); // "00ff10"
 * ```
 *
 * @since 1.0.0
 */

export function encodeHex(bytes: readonly u8[], out: u8[]): u8[] | Error {
    if (out.len < bytes.len * 2) throw HexError.ShortBuffer;
    for (const byte, i of bytes) {
        out[2 * i] = Digits[(byte >> 4) as usize];
        out[2 * i + 1] = Digits[(byte & 0x0F) as usize];
    }
    return out[0..bytes.len * 2];
}

/**
 * Reads hex text back into bytes.
 *
 * @param text - The hex digits, in either case
 * @param out - The buffer for the bytes, at least half as long as `text`
 * @returns The part of `out` that holds the bytes
 * @throws HexError.OddLength when `text` has an odd number of digits
 * @throws HexError.BadDigit when `text` holds a character that isn't a hex digit
 * @throws HexError.ShortBuffer when `out` is too small
 *
 * @remarks
 * It checks the length before writing anything, but a bad digit may leave the bytes before it written.
 * It takes no `0x` prefix and no separators.
 *
 * @example
 * ```hx
 * let out: u8[3] = undefined;
 * try decodeHex("00FF10", &out); // [0x00, 0xFF, 0x10]
 * ```
 *
 * @since 1.0.0
 */

export function decodeHex(text: readonly u8[], out: u8[]): u8[] | Error {
    if (text.len % 2 != 0) throw HexError.OddLength;
    const n = text.len / 2;
    if (out.len < n) throw HexError.ShortBuffer;
    for (const i of 0..n) {
        const high = try digit(text[2 * i]);
        const low = try digit(text[2 * i + 1]);
        out[i] = (high << 4) | low;
    }
    return out[0..n];
}
