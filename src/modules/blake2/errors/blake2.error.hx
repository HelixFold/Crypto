/**
 * The errors that starting or finishing a BLAKE2 hash can throw.
 *
 * @remarks
 * BLAKE2 takes its output length and key as parameters,
 * so a length outside what the variant allows is an error rather than a silent clamp.
 *
 * @example
 * ```hx
 * Blake2b.init(65, ""); // throws Blake2Error.BadOutputLength
 * ```
 *
 * @since 1.0.0
 */

export error Blake2Error {
    /**
     * The output length is 0 or longer than the variant allows.
     *
     * @remarks
     * BLAKE2b gives 1 to 64 bytes, and BLAKE2s gives 1 to 32.
     *
     * @example
     * ```hx
     * Blake2s.init(33, ""); // throws Blake2Error.BadOutputLength
     * ```
     *
     * @since 1.0.0
     */

    BadOutputLength,

    /**
     * The key is longer than the variant allows.
     *
     * @remarks
     * BLAKE2b takes a key of up to 64 bytes, and BLAKE2s one of up to 32.
     * Hash a longer secret down first, or use HMAC.
     *
     * @example
     * ```hx
     * Blake2s.init(32, key[0..33]); // throws Blake2Error.BadKeyLength
     * ```
     *
     * @since 1.0.0
     */

    BadKeyLength,

    /**
     * The output buffer is shorter than the output length that the hash started with.
     *
     * @remarks
     * Finishing writes exactly the output length, so the buffer needs at least that many bytes.
     *
     * @example
     * ```hx
     * let hash = try Blake2b.init(32, "");
     * hash.finish(out[0..16]); // throws Blake2Error.ShortBuffer
     * ```
     *
     * @since 1.0.0
     */

    ShortBuffer,
}
