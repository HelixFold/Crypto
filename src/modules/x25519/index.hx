/**
 * Exports
 */

export { X25519Error } from "@x25519/errors/x25519.error";

/**
 * Imports
 */

import { X25519Error } from "@x25519/errors/x25519.error";
import { FieldOne, FieldZero, add, inverse, mul, pack25519, sel25519, square, sub, unpack25519 } from "@curve25519";

/**
 * The constant (486662 - 2) / 4, which is 121665, as a field element.
 *
 * @remarks
 * RFC 7748 calls it `a24`, and each step of the ladder multiplies by it when it doubles.
 * Its two limbs are `0xDB41` and `1`, since 121665 is `0x1DB41`.
 *
 * @since 1.0.0
 */

const A24: i64[16] = [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/**
 * Computes the X25519 function of RFC 7748 on a scalar and a u-coordinate.
 *
 * @param scalar - The 32-byte private scalar, which is clamped before use
 * @param point - The 32-byte u-coordinate of the other side, such as a public key
 * @returns The 32-byte u-coordinate of the scalar times the point
 * @throws X25519Error.BadKeyLength when `scalar` or `point` is not 32 bytes long
 * @throws X25519Error.LowOrderPoint when the result is 32 zero bytes
 *
 * @remarks
 * It follows `crypto_scalarmult` of TweetNaCl.
 * The scalar is clamped as RFC 7748 asks, clearing its low 3 bits and bit 255 and setting bit 254,
 * so any 32 bytes work as a private key.
 * Bit 255 of the point is ignored, and a u-coordinate of 2^255 - 19 or more is taken modulo 2^255 - 19.
 * A Montgomery ladder runs over bits 254 down to 0, and {@link sel25519} swaps its two points under a mask,
 * so neither the branches nor the memory accesses depend on the scalar.
 * A point of small order gives 32 zero bytes, which it reports as {@link X25519Error.LowOrderPoint}
 * instead of handing back a secret that an attacker can predict.
 * The package has no random source, so the caller must draw the private scalar from a cryptographic one.
 *
 * @example
 * ```hx
 * const alicePublic = try x25519Base(&alicePrivate);
 * const bobPublic = try x25519Base(&bobPrivate);
 * try x25519(&alicePrivate, &bobPublic); // "4a5d9d5b...1e161742"
 * try x25519(&bobPrivate, &alicePublic); // "4a5d9d5b...1e161742", the same shared secret
 * ```
 *
 * @see x25519Base
 * @since 1.0.0
 */

export function x25519(scalar: readonly u8[], point: readonly u8[]): u8[32] | Error {
    if (scalar.len != 32 || point.len != 32) throw X25519Error.BadKeyLength;
    let z: u8[32] = undefined;
    for (const byte, i of scalar) z[i] = byte;
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;

    const x = unpack25519(point);
    let a = FieldOne;
    let b = x;
    let c = FieldZero;
    let d = FieldOne;
    for (const k of 0..255) {
        const i = 254 - k;
        const bit = ((z[i >> 3] >> ((i & 7) as u8)) & 1) as i64;
        sel25519(&a, &b, bit);
        sel25519(&c, &d, bit);
        let e = add(a, c);
        a = sub(a, c);
        c = add(b, d);
        b = sub(b, d);
        d = square(e);
        const f = square(a);
        a = mul(c, a);
        c = mul(b, e);
        e = add(a, c);
        a = sub(a, c);
        b = square(a);
        c = sub(d, f);
        a = mul(c, A24);
        a = add(a, d);
        c = mul(c, a);
        a = mul(d, f);
        d = mul(b, x);
        b = square(e);
        sel25519(&a, &b, bit);
        sel25519(&c, &d, bit);
    }

    const out = pack25519(mul(a, inverse(c)));
    let folded: u8 = 0;
    for (const byte of out) folded |= byte;
    if (folded == 0) throw X25519Error.LowOrderPoint;
    return out;
}

/**
 * Computes the public key of an X25519 private key, the scalar times the base point 9.
 *
 * @param scalar - The 32-byte private scalar, which is clamped before use
 * @returns The 32-byte public key to send to the other side
 * @throws X25519Error.BadKeyLength when `scalar` is not 32 bytes long
 *
 * @remarks
 * It calls {@link x25519} with the u-coordinate 9, followed by 31 zero bytes, as RFC 7748 section 6.1 does.
 * The base point has a large prime order, so a clamped scalar never gives 32 zero bytes here.
 * The package has no random source, so the caller must draw the private scalar from a cryptographic one,
 * as 32 uniformly random bytes.
 *
 * @example
 * ```hx
 * try x25519Base(&alicePrivate); // "8520f009...aa9b4e6a" for the RFC 7748 key of Alice
 * ```
 *
 * @see x25519
 * @since 1.0.0
 */

export function x25519Base(scalar: readonly u8[]): u8[32] | Error {
    let base: u8[32] = undefined;
    for (const _, i of base) base[i] = 0;
    base[0] = 9;
    const out = try x25519(scalar, &base);
    return out;
}
