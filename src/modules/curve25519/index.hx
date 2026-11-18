/**
 * The field element 0, with every limb zero.
 *
 * @remarks
 * A field element of GF(2^255 - 19) is an `i64[16]` of 16 limbs, least significant first,
 * whose value is the sum of limb `i` times 2^(16 * i).
 * Copy it into a `let` to start a value that the code builds up.
 *
 * @example
 * ```hx
 * pack25519(FieldZero); // 32 zero bytes
 * ```
 *
 * @since 1.0.0
 */

export const FieldZero: i64[16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/**
 * The field element 1, the identity of {@link mul}.
 *
 * @remarks
 * Its low limb is 1 and every other limb is zero.
 * The X25519 ladder and the Ed25519 neutral point both start from it.
 *
 * @example
 * ```hx
 * pack25519(FieldOne); // [1, 0, 0, ...]
 * ```
 *
 * @since 1.0.0
 */

export const FieldOne: i64[16] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/**
 * Carries a field element so that every limb fits in 16 bits again, in place.
 *
 * @param o - The field element to carry
 *
 * @remarks
 * It follows `car25519` of TweetNaCl.
 * Each limb adds 2^16 and gives the bits above its low 16 to the next limb, less the 1 that it borrowed.
 * The top limb wraps around into limb 0 multiplied by 38, since 2^256 is 38 modulo 2^255 - 19.
 * A limb may be negative before the call, so the carry is an arithmetic right shift,
 * and the carry leaves the limb by multiplication by 65536, never by a left shift of a negative value.
 * The value stays the same modulo 2^255 - 19, but it is not yet fully reduced.
 * The loop never branches on a limb, so its timing depends only on the fixed index.
 *
 * @example
 * ```hx
 * let o = FieldZero;
 * o[0] = 65541;
 * car25519(&o);
 * o[0]; // 5
 * o[1]; // 1
 * ```
 *
 * @since 1.0.0
 */

export function car25519(o: *i64[16]): void {
    for (const i of 0..16) {
        o[i] += 65536;
        const c = o[i] >> 16;
        if (i < 15) o[i + 1] += c - 1;
        else o[0] += 38 * (c - 1);
        o[i] -= c * 65536;
    }
}

/**
 * Swaps two field elements when a bit is 1 and leaves them alone when it is 0, in constant time.
 *
 * @param p - The first field element
 * @param q - The second field element
 * @param b - The bit, which must be 0 or 1
 *
 * @remarks
 * It follows `sel25519` of TweetNaCl.
 * The bit becomes a mask of all ones or all zeros, and each limb pair swaps through an XOR under that mask,
 * so neither the branches nor the memory accesses depend on the bit.
 * Any other value of `b` mixes the limbs, so pass only a bit.
 * The two pointers must point at different elements.
 *
 * @example
 * ```hx
 * let p = FieldZero;
 * let q = FieldOne;
 * sel25519(&p, &q, 1);
 * p[0]; // 1
 * q[0]; // 0
 * ```
 *
 * @since 1.0.0
 */

export function sel25519(p: *i64[16], q: *i64[16], b: i64): void {
    const mask = 0 - b;
    for (const i of 0..16) {
        const t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/**
 * Writes a field element as its 32 canonical bytes, little-endian.
 *
 * @param n - The field element
 * @returns The bytes of the value reduced below 2^255 - 19, so bit 255 is always 0
 *
 * @remarks
 * It follows `pack25519` of TweetNaCl.
 * Three carries bring every limb into 16 bits, and then two rounds subtract 2^255 - 19
 * and keep the difference only when it did not borrow, through {@link sel25519}.
 * The borrow between limbs comes from an arithmetic right shift of a limb that may be negative.
 * It takes the same time for every value, so it may pack a secret.
 *
 * @example
 * ```hx
 * pack25519(FieldOne);              // [1, 0, 0, ...]
 * pack25519(unpack25519(&modulus)); // 32 zero bytes, since 2^255 - 19 reduces to 0
 * ```
 *
 * @since 1.0.0
 */

export function pack25519(n: i64[16]): u8[32] {
    let t = n;
    car25519(&t);
    car25519(&t);
    car25519(&t);
    let m: i64[16] = undefined;
    for (const _ of 0..2) {
        m[0] = t[0] - 0xFFED;
        for (const i of 1..15) {
            m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xFFFF;
        }
        m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
        const b = (m[15] >> 16) & 1;
        m[14] &= 0xFFFF;
        sel25519(&t, &m, 1 - b);
    }

    let out: u8[32] = undefined;
    for (const i of 0..16) {
        out[2 * i] = (t[i] & 0xFF) as u8;
        out[2 * i + 1] = ((t[i] >> 8) & 0xFF) as u8;
    }
    return out;
}

/**
 * Reads 32 little-endian bytes as a field element.
 *
 * @param n - The bytes, at least 32 of them
 * @returns The field element, with bit 255 of the input cleared
 *
 * @remarks
 * It follows `unpack25519` of TweetNaCl.
 * Each pair of bytes becomes one limb, and bit 255 is dropped as RFC 7748 asks of a u-coordinate.
 * A value from 2^255 - 19 up to 2^255 - 1 is kept as it is and works like its reduction,
 * so compare its {@link pack25519} with the input to detect a non-canonical encoding.
 * Only the first 32 bytes are read, and a shorter slice fails the bounds check.
 *
 * @example
 * ```hx
 * let bytes: u8[32] = undefined;
 * for (const _, i of bytes) bytes[i] = 0xFF;
 * const n = unpack25519(&bytes);
 * n[15];          // 0x7FFF, since bit 255 is dropped
 * pack25519(n);   // [0x12, 0, 0, ...], since 2^255 - 1 is 18 modulo 2^255 - 19
 * ```
 *
 * @since 1.0.0
 */

export function unpack25519(n: readonly u8[]): i64[16] {
    let o: i64[16] = undefined;
    for (const i of 0..16) o[i] = (n[2 * i] as i64) + (n[2 * i + 1] as i64) * 256;
    o[15] &= 0x7FFF;
    return o;
}

/**
 * Tells whether two field elements hold the same value modulo 2^255 - 19.
 *
 * @param a - The first field element
 * @param b - The second field element
 * @returns `true` when both pack to the same bytes
 *
 * @remarks
 * It packs both and folds the XOR of every byte together, so the comparison reads all 32 bytes.
 * Two different limb layouts of the same value compare equal.
 *
 * @example
 * ```hx
 * equal25519(unpack25519(&modulus), FieldZero); // true
 * equal25519(FieldOne, FieldZero);              // false
 * ```
 *
 * @since 1.0.0
 */

export function equal25519(a: i64[16], b: i64[16]): bool {
    const x = pack25519(a);
    const y = pack25519(b);
    let diff: u8 = 0;
    for (const byte, i of x) diff |= byte ^ y[i];
    return diff == 0;
}

/**
 * Tells the low bit of a field element once it is reduced.
 *
 * @param a - The field element
 * @returns 1 when the reduced value is odd, and 0 when it is even
 *
 * @remarks
 * It follows `par25519` of TweetNaCl.
 * Ed25519 stores this bit of x in the top bit of a compressed point, and calls it the sign of x.
 *
 * @example
 * ```hx
 * parity25519(FieldOne);                // 1
 * parity25519(sub(FieldZero, FieldOne)); // 0, since 2^255 - 20 is even
 * ```
 *
 * @since 1.0.0
 */

export function parity25519(a: i64[16]): u8 {
    const bytes = pack25519(a);
    return bytes[0] & 1;
}

/**
 * Adds two field elements without carrying.
 *
 * @param a - The first field element
 * @param b - The second field element
 * @returns Their sum, limb by limb
 *
 * @remarks
 * It follows `A` of TweetNaCl.
 * The limbs grow by at most one bit, which {@link mul} absorbs, so no carry is needed here.
 *
 * @example
 * ```hx
 * pack25519(add(FieldOne, FieldOne)); // [2, 0, 0, ...]
 * ```
 *
 * @since 1.0.0
 */

export function add(a: i64[16], b: i64[16]): i64[16] {
    let o: i64[16] = undefined;
    for (const i of 0..16) o[i] = a[i] + b[i];
    return o;
}

/**
 * Subtracts one field element from another without carrying.
 *
 * @param a - The field element to subtract from
 * @param b - The field element to subtract
 * @returns Their difference, limb by limb
 *
 * @remarks
 * It follows `Z` of TweetNaCl.
 * A limb may turn negative, which {@link car25519} and {@link pack25519} handle.
 *
 * @example
 * ```hx
 * pack25519(sub(FieldZero, FieldOne)); // [0xEC, 0xFF, ..., 0xFF, 0x7F], which is 2^255 - 20
 * ```
 *
 * @since 1.0.0
 */

export function sub(a: i64[16], b: i64[16]): i64[16] {
    let o: i64[16] = undefined;
    for (const i of 0..16) o[i] = a[i] - b[i];
    return o;
}

/**
 * Multiplies two field elements modulo 2^255 - 19.
 *
 * @param a - The first field element
 * @param b - The second field element
 * @returns Their product, carried twice
 *
 * @remarks
 * It follows `M` of TweetNaCl.
 * The schoolbook product fills 31 limbs, and limbs 16 to 30 fold back into limbs 0 to 14 multiplied by 38.
 * Two carries then bring the limbs close to 16 bits.
 * The limbs never pass 2^44 in magnitude on the way, so plain `i64` arithmetic never overflows.
 * Both inputs may be the same element, and the result is a new array.
 *
 * @example
 * ```hx
 * pack25519(mul(add(FieldOne, FieldOne), add(FieldOne, FieldOne))); // [4, 0, 0, ...]
 * ```
 *
 * @since 1.0.0
 */

export function mul(a: i64[16], b: i64[16]): i64[16] {
    let t: i64[31] = undefined;
    for (const i of 0..31) t[i] = 0;
    for (const i of 0..16) {
        for (const j of 0..16) t[i + j] += a[i] * b[j];
    }
    for (const i of 0..15) t[i] += 38 * t[i + 16];

    let o: i64[16] = undefined;
    for (const i of 0..16) o[i] = t[i];
    car25519(&o);
    car25519(&o);
    return o;
}

/**
 * Squares a field element modulo 2^255 - 19.
 *
 * @param a - The field element
 * @returns Its square
 *
 * @remarks
 * It follows `S` of TweetNaCl, which multiplies the element by itself through {@link mul}.
 *
 * @example
 * ```hx
 * pack25519(square(add(FieldOne, FieldOne))); // [4, 0, 0, ...]
 * ```
 *
 * @since 1.0.0
 */

export function square(a: i64[16]): i64[16] {
    return mul(a, a);
}

/**
 * Inverts a field element modulo 2^255 - 19.
 *
 * @param a - The field element
 * @returns Its inverse, or 0 when `a` is 0
 *
 * @remarks
 * It follows `inv25519` of TweetNaCl and raises `a` to the power 2^255 - 21 by Fermat's little theorem.
 * The chain of squarings and multiplications is fixed by the exponent, so its timing does not depend on `a`.
 *
 * @example
 * ```hx
 * pack25519(inverse(add(FieldOne, FieldOne))); // [0xF7, 0xFF, ..., 0xFF, 0x3F], which is (p + 1) / 2
 * ```
 *
 * @since 1.0.0
 */

export function inverse(a: i64[16]): i64[16] {
    let c = a;
    for (const k of 0..254) {
        const e = 253 - k;
        c = square(c);
        if (e != 2 && e != 4) c = mul(c, a);
    }
    return c;
}

/**
 * Raises a field element to the power (2^255 - 21) / 8, which is 2^252 - 3.
 *
 * @param a - The field element
 * @returns `a` to the power 2^252 - 3
 *
 * @remarks
 * It follows `pow2523` of TweetNaCl.
 * Ed25519 point decompression uses it to take the square root of a ratio in one exponentiation.
 * The chain of squarings and multiplications is fixed by the exponent, so its timing does not depend on `a`.
 *
 * @example
 * ```hx
 * pack25519(pow2523(FieldOne)); // [1, 0, 0, ...]
 * ```
 *
 * @since 1.0.0
 */

export function pow2523(a: i64[16]): i64[16] {
    let c = a;
    for (const k of 0..251) {
        const e = 250 - k;
        c = square(c);
        if (e != 1) c = mul(c, a);
    }
    return c;
}
