/**
 * Imports
 */

import { BaseX, BaseY, EdwardsD, EdwardsD2, SqrtM1 } from "@ed25519/constants/ed25519.constant";
import {
    FieldOne, FieldZero, add, equal25519, inverse, mul, pack25519, parity25519, pow2523, sel25519, square, sub,
    unpack25519,
} from "@curve25519";

/**
 * A point of edwards25519 in extended coordinates.
 *
 * @remarks
 * The affine point is (x / z, y / z), and `t` holds x * y / z, as RFC 8032 section 5.1.4 describes.
 * Extended coordinates let {@link pointAdd} add and double with the same formula and no inversion,
 * so one inversion in {@link packPoint} finishes a whole scalar multiplication.
 * The neutral point is (0, 1, 1, 0).
 *
 * @example
 * ```hx
 * const neutral = Point { x: FieldZero, y: FieldOne, z: FieldOne, t: FieldZero };
 * packPoint(neutral); // [1, 0, 0, ...]
 * ```
 *
 * @since 1.0.0
 */

export struct Point {
    /**
     * The projective x-coordinate, X in RFC 8032.
     *
     * @remarks
     * The affine x is this divided by {@link Point.z}.
     *
     * @example
     * ```hx
     * scalarMultBase(&one).x; // the x of B, scaled by z
     * ```
     *
     * @since 1.0.0
     */

    x: i64[16],

    /**
     * The projective y-coordinate, Y in RFC 8032.
     *
     * @remarks
     * The affine y is this divided by {@link Point.z}, and it is what a compressed point stores.
     *
     * @example
     * ```hx
     * scalarMultBase(&one).y; // the y of B, scaled by z
     * ```
     *
     * @since 1.0.0
     */

    y: i64[16],

    /**
     * The common denominator, Z in RFC 8032.
     *
     * @remarks
     * It is never zero for a point on the curve.
     *
     * @example
     * ```hx
     * scalarMultBase(&one).z; // nonzero
     * ```
     *
     * @since 1.0.0
     */

    z: i64[16],

    /**
     * The product x * y / z, T in RFC 8032.
     *
     * @remarks
     * {@link pointAdd} uses it in place of a multiplication, and it must stay consistent with the other three.
     *
     * @example
     * ```hx
     * scalarMultBase(&one).t; // the x * y of B, scaled by z
     * ```
     *
     * @since 1.0.0
     */

    t: i64[16],
}

/**
 * Adds two points of edwards25519.
 *
 * @param p - The first point
 * @param q - The second point
 * @returns Their sum
 *
 * @remarks
 * It follows `add` of TweetNaCl, the unified addition of RFC 8032 section 5.1.4.
 * The formula is complete, so it also doubles a point and handles the neutral point without a branch.
 * Both inputs may be the same point.
 *
 * @example
 * ```hx
 * const b = scalarMultBase(&one);
 * packPoint(pointAdd(b, b)); // "c9a3f86a...f3cd6022", the encoding of 2 * B
 * ```
 *
 * @since 1.0.0
 */

export function pointAdd(p: Point, q: Point): Point {
    const a = mul(sub(p.y, p.x), sub(q.y, q.x));
    const b = mul(add(p.x, p.y), add(q.x, q.y));
    const c = mul(mul(p.t, q.t), EdwardsD2);
    const zz = mul(p.z, q.z);
    const d = add(zz, zz);
    const e = sub(b, a);
    const f = sub(d, c);
    const g = add(d, c);
    const h = add(b, a);

    return Point { x: mul(e, f), y: mul(h, g), z: mul(g, f), t: mul(e, h) };
}

/**
 * Swaps two points when a bit is 1 and leaves them alone when it is 0, in constant time.
 *
 * @param p - The first point
 * @param q - The second point
 * @param bit - The bit, which must be 0 or 1
 *
 * @remarks
 * It follows `cswap` of TweetNaCl and runs {@link sel25519} on each of the four coordinates,
 * so neither the branches nor the memory accesses depend on the bit.
 *
 * @example
 * ```hx
 * pointSwap(&p, &q, 1); // p and q have traded places
 * ```
 *
 * @since 1.0.0
 */

export function pointSwap(p: *Point, q: *Point, bit: i64): void {
    sel25519(&p.x, &q.x, bit);
    sel25519(&p.y, &q.y, bit);
    sel25519(&p.z, &q.z, bit);
    sel25519(&p.t, &q.t, bit);
}

/**
 * Compresses a point into its 32-byte encoding.
 *
 * @param p - The point
 * @returns The affine y, little-endian, with the low bit of the affine x in bit 255
 *
 * @remarks
 * It follows `pack` of TweetNaCl and the encoding of RFC 8032 section 5.1.2.
 * One inversion of z gives the affine coordinates, and the encoding is always canonical.
 * It takes the same time for every point, so it may encode a secret nonce point.
 *
 * @example
 * ```hx
 * packPoint(scalarMultBase(&one)); // "58666666...66666666", the encoding of B
 * ```
 *
 * @since 1.0.0
 */

export function packPoint(p: Point): u8[32] {
    const zi = inverse(p.z);
    const tx = mul(p.x, zi);
    const ty = mul(p.y, zi);
    let r = pack25519(ty);
    r[31] ^= parity25519(tx) << 7;
    return r;
}

/**
 * Multiplies a point by a 256-bit scalar, in constant time.
 *
 * @param base - The point to multiply
 * @param scalar - The scalar, 32 bytes, little-endian
 * @returns The scalar times the point
 *
 * @remarks
 * It follows `scalarmult` of TweetNaCl, a ladder over bits 255 down to 0.
 * Every bit costs one addition and one doubling, and {@link pointSwap} chooses between them under a mask,
 * so neither the branches nor the memory accesses depend on the scalar.
 * All 256 bits count, and the scalar need not be reduced.
 * Only the first 32 bytes of `scalar` are read, and a shorter slice fails the bounds check.
 *
 * @example
 * ```hx
 * packPoint(scalarMult(scalarMultBase(&one), &two)); // "c9a3f86a...f3cd6022", the encoding of 2 * B
 * ```
 *
 * @since 1.0.0
 */

export function scalarMult(base: Point, scalar: readonly u8[]): Point {
    let p = Point { x: FieldZero, y: FieldOne, z: FieldOne, t: FieldZero };
    let q = base;
    for (const k of 0..256) {
        const i = 255 - k;
        const bit = ((scalar[i >> 3] >> ((i & 7) as u8)) & 1) as i64;
        pointSwap(&p, &q, bit);
        q = pointAdd(q, p);
        p = pointAdd(p, p);
        pointSwap(&p, &q, bit);
    }
    return p;
}

/**
 * Multiplies the base point B by a 256-bit scalar, in constant time.
 *
 * @param scalar - The scalar, 32 bytes, little-endian
 * @returns The scalar times B
 *
 * @remarks
 * It follows `scalarbase` of TweetNaCl,
 * which builds B from {@link BaseX} and {@link BaseY} and calls {@link scalarMult}.
 * Signing uses it for the public key and the nonce point, so it must stay constant-time.
 *
 * @example
 * ```hx
 * packPoint(scalarMultBase(&zero)); // [1, 0, 0, ...], the neutral point
 * packPoint(scalarMultBase(&one));  // "58666666...66666666", the encoding of B
 * ```
 *
 * @since 1.0.0
 */

export function scalarMultBase(scalar: readonly u8[]): Point {
    const base = Point { x: BaseX, y: BaseY, z: FieldOne, t: mul(BaseX, BaseY) };
    return scalarMult(base, scalar);
}

/**
 * Decompresses a public key and negates it, or gives `null` when it doesn't decode.
 *
 * @param bytes - The 32-byte encoding
 * @returns The negated point -A, or `null` when the bytes are not a valid encoding
 *
 * @remarks
 * It follows `unpackneg` of TweetNaCl with the stricter checks of RFC 8032 section 5.1.3.
 * The point is rejected when y is 2^255 - 19 or more, when (y^2 - 1) / (d * y^2 + 1) has no square root,
 * or when x is 0 but the sign bit is 1.
 * The square root comes from one call of {@link pow2523},
 * with a multiplication by {@link SqrtM1} when the first candidate squares to the negated value.
 * Verification wants -A, so the x with the opposite sign bit is the one kept.
 * The branches here depend only on the public key, which is not secret.
 * Only the first 32 bytes of `bytes` are read.
 *
 * @example
 * ```hx
 * packPoint(unpackNegative(&encodedBase) ?? neutral); // "58666666...666666e6", the encoding of -B
 * unpackNegative(&two);                               // null, since y = 2 is not on the curve
 * ```
 *
 * @since 1.0.0
 */

export function unpackNegative(bytes: readonly u8[]): ?Point {
    const y = unpack25519(bytes);
    const packed = pack25519(y);
    let diff: u8 = packed[31] ^ (bytes[31] & 0x7F);
    for (const i of 0..31) diff |= packed[i] ^ bytes[i];
    if (diff != 0) return null;

    const one = FieldOne;
    let num = square(y);
    let den = mul(num, EdwardsD);
    num = sub(num, one);
    den = add(one, den);
    const den2 = square(den);
    const den4 = square(den2);
    const den6 = mul(den4, den2);
    let t = mul(den6, num);
    t = mul(t, den);
    t = pow2523(t);
    t = mul(t, num);
    t = mul(t, den);
    t = mul(t, den);
    let x = mul(t, den);

    if (!equal25519(mul(square(x), den), num)) x = mul(x, SqrtM1);
    if (!equal25519(mul(square(x), den), num)) return null;
    const sign = bytes[31] >> 7;
    if (sign == 1 && equal25519(x, FieldZero)) return null;
    if (parity25519(x) == sign) x = sub(FieldZero, x);

    return Point { x: x, y: y, z: one, t: mul(x, y) };
}
