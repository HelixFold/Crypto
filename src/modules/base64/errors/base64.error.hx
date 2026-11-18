/**
 * The errors that encoding or decoding base64 can throw.
 *
 * @remarks
 * Both directions write into a buffer that the caller passes,
 * so a buffer that is too small is an error rather than an allocation.
 * Decoding is strict, so every byte string has exactly one text that decodes to it.
 *
 * @example
 * ```hx
 * decodeBase64("Zg=", &out); // throws Base64Error.BadLength
 * ```
 *
 * @since 1.0.0
 */

export error Base64Error {
    /**
     * The output buffer is too small for the result.
     *
     * @remarks
     * Encoding needs four characters for every three bytes, rounded up.
     * Decoding needs three bytes for every four characters, less one per padding character.
     *
     * @example
     * ```hx
     * encodeBase64("abc", out[0..3]); // throws Base64Error.ShortBuffer
     * ```
     *
     * @since 1.0.0
     */

    ShortBuffer,

    /**
     * The text has a length that no encoding produces.
     *
     * @remarks
     * Padded text always comes in groups of four characters.
     * Text without padding never leaves a single character over, since one character holds only 6 bits.
     *
     * @example
     * ```hx
     * decodeBase64("Zg=", &out);     // throws Base64Error.BadLength
     * decodeBase64Url("Zm9vY", &out); // throws Base64Error.BadLength
     * ```
     *
     * @since 1.0.0
     */

    BadLength,

    /**
     * The text holds a character outside the alphabet of its variant.
     *
     * @remarks
     * Whitespace and line breaks count as bad characters too, so strip them first.
     * The standard variant takes `+` and `/`, and the URL-safe variant takes `-` and `_`, never both.
     *
     * @example
     * ```hx
     * decodeBase64("Zm 9", &out);  // throws Base64Error.BadCharacter
     * decodeBase64Url("+/8", &out); // throws Base64Error.BadCharacter
     * ```
     *
     * @since 1.0.0
     */

    BadCharacter,

    /**
     * The text has `=` somewhere other than the last one or two places of padded text.
     *
     * @remarks
     * Standard text ends in at most two `=` characters, and only where the last group is short.
     * URL-safe text takes no padding at all.
     *
     * @example
     * ```hx
     * decodeBase64("Z===", &out);   // throws Base64Error.BadPadding
     * decodeBase64Url("Zg==", &out); // throws Base64Error.BadPadding
     * ```
     *
     * @since 1.0.0
     */

    BadPadding,

    /**
     * The last character before the padding has bits set that no byte uses.
     *
     * @remarks
     * A short last group leaves 2 or 4 bits of its last character unused, and an encoder always writes them as zero.
     * Rejecting them keeps a second text from decoding to the same bytes.
     *
     * @example
     * ```hx
     * decodeBase64("Zh==", &out); // throws Base64Error.TrailingBits
     * ```
     *
     * @since 1.0.0
     */

    TrailingBits,
}
