/**
 * Imports
 */

import { Order } from "@ed25519/constants/ed25519.constant";

/**
 * Reduces a number, held as 64 signed byte-sized limbs, modulo the group order L.
 *
 * @param x - The limbs, least significant first, which the reduction overwrites
 * @returns The value modulo L, as 32 little-endian bytes
 *
 * @remarks
 * It follows `modL` of TweetNaCl.
 * Limbs 63 down to 32 fold into the lower ones by subtracting 16 times the limb times L,
 * since 2^256 is 16 times L minus a small value, and each step carries with an arithmetic right shift.
 * A last pass subtracts the top bits once more and spreads the carry, so the result is fully reduced.
 * The limbs may hold sums of byte products, as signing leaves them, and they never pass 2^44 in magnitude.
 * Neither the branches nor the memory accesses depend on the limbs, so it may reduce a secret scalar.
 *
 * @example
 * ```hx
 * let x: i64[64] = undefined;
 * for (const _, i of x) x[i] = 0;
 * for (const byte, i of Order) x[i] = byte as i64;
 * x[0] += 5;
 * modOrder(&x); // [5, 0, 0, ...], since L + 5 is 5 modulo L
 * ```
 *
 * @since 1.0.0
 */

export function modOrder(x: *i64[64]): u8[32] {
    for (const k of 0..32) {
        const i = 63 - k;
        const start = i - 32;
        const end = i - 12;
        let carry: i64 = 0;
        for (const j of start..end) {
            x[j] += carry - 16 * x[i] * (Order[j - start] as i64);
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[end] += carry;
        x[i] = 0;
    }

    let rest: i64 = 0;
    for (const j of 0..32) {
        x[j] += rest - (x[31] >> 4) * (Order[j] as i64);
        rest = x[j] >> 8;
        x[j] &= 255;
    }
    for (const j of 0..32) x[j] -= rest * (Order[j] as i64);

    let out: u8[32] = undefined;
    for (const i of 0..32) {
        x[i + 1] += x[i] >> 8;
        out[i] = (x[i] & 255) as u8;
    }
    return out;
}

/**
 * Reduces a 64-byte hash modulo the group order L.
 *
 * @param bytes - The 64 bytes, little-endian, as SHA-512 gives them
 * @returns The value modulo L, as 32 little-endian bytes
 *
 * @remarks
 * It follows `reduce` of TweetNaCl, which spreads the bytes into limbs and calls {@link modOrder}.
 * Ed25519 reduces both the nonce hash and the challenge hash this way.
 * Only the first 64 bytes of `bytes` are read, and a shorter slice fails the bounds check.
 *
 * @example
 * ```hx
 * reduceScalar(&digest); // the digest read as a number, modulo L
 * ```
 *
 * @since 1.0.0
 */

export function reduceScalar(bytes: readonly u8[]): u8[32] {
    let x: i64[64] = undefined;
    for (const i of 0..64) x[i] = bytes[i] as i64;
    return modOrder(&x);
}

/**
 * Tells whether a 32-byte scalar is below the group order L.
 *
 * @param s - The scalar, 32 bytes, little-endian
 * @returns `true` when the value is less than L
 *
 * @remarks
 * RFC 8032 section 5.1.7 rejects a signature whose S is L or more,
 * since adding L to S gives a second encoding that would otherwise verify too.
 * It compares from the most significant byte down and stops at the first difference,
 * which is safe because S is part of a public signature.
 *
 * @example
 * ```hx
 * isCanonicalScalar(&Order); // false
 * isCanonicalScalar(&zero);  // true
 * ```
 *
 * @since 1.0.0
 */

export function isCanonicalScalar(s: readonly u8[]): bool {
    for (const k of 0..32) {
        const i = 31 - k;
        if (s[i] < Order[i]) return true;
        if (s[i] > Order[i]) return false;
    }
    return false;
}
