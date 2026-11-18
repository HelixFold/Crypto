/**
 * Exports
 */

export { Base64Error } from "@base64/errors/base64.error";

/**
 * Imports
 */

import { Base64Error } from "@base64/errors/base64.error";

/**
 * Tells whether one small number is at least another, as 1 or 0, without a branch.
 *
 * @param a - A number from 0 to 255
 * @param b - A number from 0 to 255
 * @returns `1` when `a >= b`, and `0` otherwise
 *
 * @remarks
 * `a + 256 - b` lies between 1 and 511 and reaches 256 exactly when `a >= b`, so bit 8 is the answer.
 * The base64 mappings combine these bits with multiplications instead of comparisons or a lookup table,
 * so their timing does not depend on the bytes, which may be a secret key.
 *
 * @since 1.0.0
 */

function atLeast(a: u32, b: u32): u32 {
    return (a + 256 - b) >> 8;
}

/**
 * Turns a 6-bit value into its base64 character.
 *
 * @param value - The value, from 0 to 63
 * @param plus - The character for 62, `+` or `-`
 * @param slash - The character for 63, `/` or `_`
 * @returns The character
 *
 * @remarks
 * It starts from `A` and adds an offset for each range that the value reaches,
 * then swaps in `plus` or `slash` for the last two values.
 * Every value runs the same arithmetic, without branches or a table indexed by the value.
 *
 * @since 1.0.0
 */

function symbol(value: u32, plus: u8, slash: u8): u8 {
    const letter = value + 65 + 6 * atLeast(value, 26) - 75 * atLeast(value, 52);
    const high = atLeast(value, 62);
    const last = atLeast(value, 63);
    const c = letter * (1 - high) + (high - last) * (plus as u32) + last * (slash as u32);

    return (c & 0xFF) as u8;
}

/**
 * Turns a base64 character into its 6-bit value plus one, or 0 for a character outside the alphabet.
 *
 * @param c - The character
 * @param plus - The character for 62, `+` or `-`
 * @param slash - The character for 63, `/` or `_`
 * @returns The value plus one, from 1 to 64, or `0` when `c` is not in the alphabet
 *
 * @remarks
 * Each of the five ranges contributes its value only when `c` falls inside it, which the multiplications select,
 * so the timing does not depend on the character.
 * Returning the value plus one leaves 0 free to mean a bad character.
 *
 * @since 1.0.0
 */

function sextet(c: u8, plus: u8, slash: u8): u32 {
    const x = c as u32;
    const upper = atLeast(x, 'A') * atLeast('Z', x);
    const lower = atLeast(x, 'a') * atLeast('z', x);
    const digit = atLeast(x, '0') * atLeast('9', x);
    const p = plus as u32;
    const s = slash as u32;
    const first = atLeast(x, p) * atLeast(p, x);
    const second = atLeast(x, s) * atLeast(s, x);

    return upper * x - upper * 64 + lower * x - lower * 70 + digit * x + digit * 5 + first * 63 + second * 64;
}

/**
 * Writes bytes as base64 with the given alphabet.
 *
 * @param bytes - The bytes
 * @param out - The buffer for the text
 * @param plus - The character for 62
 * @param slash - The character for 63
 * @param padded - Whether to fill the last group to four characters with `=`
 * @returns The part of `out` that holds the text
 * @throws Base64Error.ShortBuffer when `out` is too small
 *
 * @remarks
 * Each group of three bytes becomes four characters, most significant bits first.
 * A last group of one or two bytes becomes two or three characters, and the padding fills it to four.
 *
 * @since 1.0.0
 */

function encode(bytes: readonly u8[], out: u8[], plus: u8, slash: u8, padded: bool): u8[] | Error {
    const groups = bytes.len / 3;
    const rest = bytes.len % 3;
    const tail: usize = rest == 0 ? 0 : padded ? 4 : rest + 1;
    const length = groups * 4 + tail;
    if (out.len < length) throw Base64Error.ShortBuffer;
    for (const g of 0..groups) {
        const word = ((bytes[3 * g] as u32) << 16) | ((bytes[3 * g + 1] as u32) << 8) | (bytes[3 * g + 2] as u32);
        out[4 * g] = symbol(word >> 18, plus, slash);
        out[4 * g + 1] = symbol((word >> 12) & 63, plus, slash);
        out[4 * g + 2] = symbol((word >> 6) & 63, plus, slash);
        out[4 * g + 3] = symbol(word & 63, plus, slash);
    }
    const at = groups * 4;
    if (rest == 1) {
        const word = (bytes[3 * groups] as u32) << 4;
        out[at] = symbol(word >> 6, plus, slash);
        out[at + 1] = symbol(word & 63, plus, slash);
        if (padded) {
            out[at + 2] = '=';
            out[at + 3] = '=';
        }
    } else if (rest == 2) {
        const word = (((bytes[3 * groups] as u32) << 8) | (bytes[3 * groups + 1] as u32)) << 2;
        out[at] = symbol(word >> 12, plus, slash);
        out[at + 1] = symbol((word >> 6) & 63, plus, slash);
        out[at + 2] = symbol(word & 63, plus, slash);
        if (padded) out[at + 3] = '=';
    }
    return out[0..length];
}

/**
 * Reads base64 text back into bytes with the given alphabet.
 *
 * @param text - The text
 * @param out - The buffer for the bytes
 * @param plus - The character for 62
 * @param slash - The character for 63
 * @param padded - Whether the text must come in groups of four with `=` padding, or must have no padding
 * @returns The part of `out` that holds the bytes
 * @throws Base64Error.BadLength when no encoding produces text of this length
 * @throws Base64Error.ShortBuffer when `out` is too small
 * @throws Base64Error.BadPadding when `=` appears where padding can't be
 * @throws Base64Error.BadCharacter when the text holds a character outside the alphabet
 * @throws Base64Error.TrailingBits when the unused bits of the last character are not zero
 *
 * @remarks
 * It looks at the length and the padding first, which depend only on the length of the bytes.
 * It then decodes every character before it reports a bad one, so the time depends only on the length.
 * A bad character may leave bytes in `out`, even when the call throws.
 *
 * @since 1.0.0
 */

function decode(text: readonly u8[], out: u8[], plus: u8, slash: u8, padded: bool): u8[] | Error {
    let body = text.len;
    if (padded) {
        if (text.len % 4 != 0) throw Base64Error.BadLength;
        if (body > 0 && text[body - 1] == '=') {
            body -= 1;
            if (text[body - 1] == '=') body -= 1;
        }
    } else if (text.len % 4 == 1) {
        throw Base64Error.BadLength;
    }
    const groups = body / 4;
    const rest = body % 4;
    const length = groups * 3 + (rest == 0 ? 0 : rest - 1);
    if (out.len < length) throw Base64Error.ShortBuffer;

    let valid: u32 = 1;
    for (const g of 0..groups) {
        const a = sextet(text[4 * g], plus, slash);
        const b = sextet(text[4 * g + 1], plus, slash);
        const c = sextet(text[4 * g + 2], plus, slash);
        const d = sextet(text[4 * g + 3], plus, slash);
        valid &= atLeast(a, 1) & atLeast(b, 1) & atLeast(c, 1) & atLeast(d, 1);
        const word = (((a + 63) & 63) << 18) | (((b + 63) & 63) << 12) | (((c + 63) & 63) << 6) | ((d + 63) & 63);
        out[3 * g] = ((word >> 16) & 0xFF) as u8;
        out[3 * g + 1] = ((word >> 8) & 0xFF) as u8;
        out[3 * g + 2] = (word & 0xFF) as u8;
    }
    let spare: u32 = 0;
    const at = groups * 4;
    if (rest >= 2) {
        const a = sextet(text[at], plus, slash);
        const b = sextet(text[at + 1], plus, slash);
        valid &= atLeast(a, 1) & atLeast(b, 1);
        let word = (((a + 63) & 63) << 6) | ((b + 63) & 63);
        if (rest == 3) {
            const c = sextet(text[at + 2], plus, slash);
            valid &= atLeast(c, 1);
            word = (word << 6) | ((c + 63) & 63);
            out[3 * groups] = ((word >> 10) & 0xFF) as u8;
            out[3 * groups + 1] = ((word >> 2) & 0xFF) as u8;
            spare = word & 3;
        } else {
            out[3 * groups] = ((word >> 4) & 0xFF) as u8;
            spare = word & 15;
        }
    }

    if (valid == 0) {
        for (const c of text[0..body]) {
            if (c == '=') throw Base64Error.BadPadding;
        }
        throw Base64Error.BadCharacter;
    }
    if (spare != 0) throw Base64Error.TrailingBits;
    return out[0..length];
}

/**
 * Writes bytes as standard base64 with padding.
 *
 * @param bytes - The bytes
 * @param out - The buffer for the text, at least `4 * ceil(bytes.len / 3)` long
 * @returns The part of `out` that holds the text
 * @throws Base64Error.ShortBuffer when `out` is too small
 *
 * @remarks
 * It uses the alphabet of RFC 4648 section 4, with `+` and `/`, and pads the last group with `=`.
 * It writes into `out` and allocates nothing, so it works without an allocator.
 * It maps each value with arithmetic instead of a lookup table, so its timing reveals nothing about the bytes.
 * Use {@link encodeBase64Url} for text that goes into a URL or a file name.
 *
 * @example
 * ```hx
 * let out: u8[8] = undefined;
 * try encodeBase64("foob", &out); // "Zm9vYg=="
 * ```
 *
 * @since 1.0.0
 */

export function encodeBase64(bytes: readonly u8[], out: u8[]): u8[] | Error {
    return try encode(bytes, out, '+', '/', true);
}

/**
 * Reads standard base64 text with padding back into bytes.
 *
 * @param text - The text, in groups of four characters with `=` padding
 * @param out - The buffer for the bytes, at least `3 * text.len / 4` long, less one per `=`
 * @returns The part of `out` that holds the bytes
 * @throws Base64Error.BadLength when the length is not a multiple of four
 * @throws Base64Error.ShortBuffer when `out` is too small
 * @throws Base64Error.BadPadding when `=` appears anywhere but the last one or two places
 * @throws Base64Error.BadCharacter when the text holds a character outside `A-Z`, `a-z`, `0-9`, `+`, and `/`
 * @throws Base64Error.TrailingBits when the unused bits of the last character are not zero
 *
 * @remarks
 * It is strict, so it takes exactly what {@link encodeBase64} writes and nothing else.
 * It rejects missing padding, whitespace, line breaks, and the URL-safe characters.
 * It decodes every character before it reports a bad one, so its timing depends only on the length.
 *
 * @example
 * ```hx
 * let out: u8[4] = undefined;
 * try decodeBase64("Zm9vYg==", &out); // "foob"
 * decodeBase64("Zm9vYg", &out);       // throws Base64Error.BadLength
 * ```
 *
 * @since 1.0.0
 */

export function decodeBase64(text: readonly u8[], out: u8[]): u8[] | Error {
    return try decode(text, out, '+', '/', true);
}

/**
 * Writes bytes as URL-safe base64 without padding.
 *
 * @param bytes - The bytes
 * @param out - The buffer for the text, at least `ceil(4 * bytes.len / 3)` long
 * @returns The part of `out` that holds the text
 * @throws Base64Error.ShortBuffer when `out` is too small
 *
 * @remarks
 * It uses the alphabet of RFC 4648 section 5, with `-` and `_` in place of `+` and `/`, and writes no padding.
 * That is the form that JWTs and most URL parameters use, and it needs no escaping in a URL or a file name.
 * It writes into `out` and allocates nothing.
 *
 * @example
 * ```hx
 * let out: u8[3] = undefined;
 * try encodeBase64Url("\xfb\xff", &out); // "-_8"
 * ```
 *
 * @since 1.0.0
 */

export function encodeBase64Url(bytes: readonly u8[], out: u8[]): u8[] | Error {
    return try encode(bytes, out, '-', '_', false);
}

/**
 * Reads URL-safe base64 text without padding back into bytes.
 *
 * @param text - The text, without `=` padding
 * @param out - The buffer for the bytes, at least `3 * text.len / 4` long, rounded down
 * @returns The part of `out` that holds the bytes
 * @throws Base64Error.BadLength when the length leaves a single character over
 * @throws Base64Error.ShortBuffer when `out` is too small
 * @throws Base64Error.BadPadding when the text holds `=`
 * @throws Base64Error.BadCharacter when the text holds a character outside `A-Z`, `a-z`, `0-9`, `-`, and `_`
 * @throws Base64Error.TrailingBits when the unused bits of the last character are not zero
 *
 * @remarks
 * It is strict, so it takes exactly what {@link encodeBase64Url} writes and nothing else.
 * It rejects padding and the standard characters `+` and `/`.
 *
 * @example
 * ```hx
 * let out: u8[2] = undefined;
 * try decodeBase64Url("-_8", &out); // [0xFB, 0xFF]
 * ```
 *
 * @since 1.0.0
 */

export function decodeBase64Url(text: readonly u8[], out: u8[]): u8[] | Error {
    return try decode(text, out, '-', '_', false);
}
