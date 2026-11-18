/**
 * The errors that encoding or decoding hex can throw.
 *
 * @remarks
 * Both directions write into a buffer that the caller passes,
 * so a buffer that is too small is an error rather than an allocation.
 *
 * @example
 * ```hx
 * decodeHex("abc", &out); // throws HexError.OddLength
 * ```
 *
 * @since 1.0.0
 */

export error HexError {
    /**
     * The output buffer is too small for the result.
     *
     * @remarks
     * Encoding needs two bytes of output per input byte, and decoding needs one per two digits.
     *
     * @example
     * ```hx
     * encodeHex("ab", out[0..3]); // throws HexError.ShortBuffer
     * ```
     *
     * @since 1.0.0
     */

    ShortBuffer,

    /**
     * The hex text has an odd number of digits, so its last byte is incomplete.
     *
     * @remarks
     * Every byte takes exactly two digits, and decoding never pads a lone digit with a zero.
     *
     * @example
     * ```hx
     * decodeHex("abc", &out); // throws HexError.OddLength
     * ```
     *
     * @since 1.0.0
     */

    OddLength,

    /**
     * The hex text holds a character other than `0-9`, `a-f`, or `A-F`.
     *
     * @remarks
     * Whitespace, a `0x` prefix, and separators count as bad digits too, so strip them first.
     *
     * @example
     * ```hx
     * decodeHex("zz", &out); // throws HexError.BadDigit
     * ```
     *
     * @since 1.0.0
     */

    BadDigit,
}
