/**
 * The curve constant d of edwards25519, which is -121665 / 121666 modulo 2^255 - 19, as a field element.
 *
 * @remarks
 * RFC 8032 section 5.1 defines the curve as -x^2 + y^2 = 1 + d * x^2 * y^2.
 * Point decompression multiplies by it to recover x from y.
 * The limbs come from computing the value and splitting it into 16-bit pieces, least significant first.
 *
 * @example
 * ```hx
 * EdwardsD[0]; // 0x78A3
 * ```
 *
 * @since 1.0.0
 */

export const EdwardsD: i64[16] = [
    0x78A3, 0x1359, 0x4DCA, 0x75EB, 0xD8AB, 0x4141, 0x0A4D, 0x0070,
    0xE898, 0x7779, 0x4079, 0x8CC7, 0xFE73, 0x2B6F, 0x6CEE, 0x5203,
];

/**
 * The constant 2 * d modulo 2^255 - 19, as a field element.
 *
 * @remarks
 * Point addition in extended coordinates multiplies `T1 * T2` by it, which saves one addition per call.
 *
 * @example
 * ```hx
 * EdwardsD2[0]; // 0xF159
 * ```
 *
 * @since 1.0.0
 */

export const EdwardsD2: i64[16] = [
    0xF159, 0x26B2, 0x9B94, 0xEBD6, 0xB156, 0x8283, 0x149A, 0x00E0,
    0xD130, 0xEEF3, 0x80F2, 0x198E, 0xFCE7, 0x56DF, 0xD9DC, 0x2406,
];

/**
 * The x-coordinate of the base point B of Ed25519, as a field element.
 *
 * @remarks
 * RFC 8032 section 5.1 picks the even x that goes with {@link BaseY}.
 *
 * @example
 * ```hx
 * BaseX[0]; // 0xD51A
 * ```
 *
 * @since 1.0.0
 */

export const BaseX: i64[16] = [
    0xD51A, 0x8F25, 0x2D60, 0xC956, 0xA7B2, 0x9525, 0xC760, 0x692C,
    0xDC5C, 0xFDD6, 0xE231, 0xC0A4, 0x53FE, 0xCD6E, 0x36D3, 0x2169,
];

/**
 * The y-coordinate of the base point B of Ed25519, which is 4 / 5 modulo 2^255 - 19, as a field element.
 *
 * @remarks
 * Its encoding is the familiar `5866...66` that opens every compressed base point.
 *
 * @example
 * ```hx
 * BaseY[0]; // 0x6658
 * ```
 *
 * @since 1.0.0
 */

export const BaseY: i64[16] = [
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
];

/**
 * A square root of -1 modulo 2^255 - 19, which is 2^((p - 1) / 4), as a field element.
 *
 * @remarks
 * Point decompression multiplies a candidate root by it when the candidate squares to the negated value.
 *
 * @example
 * ```hx
 * pack25519(square(SqrtM1)); // [0xEC, 0xFF, ..., 0xFF, 0x7F], which is -1
 * ```
 *
 * @since 1.0.0
 */

export const SqrtM1: i64[16] = [
    0xA0B0, 0x4A0E, 0x1B27, 0xC4EE, 0xE478, 0xAD2F, 0x1806, 0x2F43,
    0xD7A7, 0x3DFB, 0x0099, 0x2B4D, 0xDF0B, 0x4FC1, 0x2480, 0x2B83,
];

/**
 * The order L of the base point, 2^252 + 27742317777372353535851937790883648493, as 32 little-endian bytes.
 *
 * @remarks
 * Every scalar of a signature is reduced modulo it,
 * and verification rejects an S of L or more so that a signature has only one valid encoding.
 *
 * @example
 * ```hx
 * Order[0];  // 0xED
 * Order[31]; // 0x10
 * ```
 *
 * @since 1.0.0
 */

export const Order: u8[32] = [
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];
