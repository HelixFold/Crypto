/**
 * The errors that the ChaCha20 stream cipher can throw.
 *
 * @remarks
 * Every check runs before the first byte of output is written,
 * so an error leaves the output buffer as it was.
 *
 * @example
 * ```hx
 * chacha20("short", &nonce, 0, "", &out); // throws ChaCha20Error.BadKeyLength
 * ```
 *
 * @since 1.0.0
 */

export error ChaCha20Error {
    /**
     * The key is not exactly 32 bytes long.
     *
     * @remarks
     * ChaCha20 takes a 256-bit key only, and a shorter key is never padded or stretched.
     *
     * @example
     * ```hx
     * chacha20Block("short", &nonce, 0); // throws ChaCha20Error.BadKeyLength
     * ```
     *
     * @since 1.0.0
     */

    BadKeyLength,

    /**
     * The nonce is not exactly 12 bytes long.
     *
     * @remarks
     * This is the 96-bit nonce of RFC 8439, not the 64-bit nonce of the original ChaCha20.
     *
     * @example
     * ```hx
     * chacha20Block(&key, "8 bytes!", 0); // throws ChaCha20Error.BadNonceLength
     * ```
     *
     * @since 1.0.0
     */

    BadNonceLength,

    /**
     * The output buffer is shorter than the input.
     *
     * @remarks
     * The cipher writes one byte of output for each byte of input.
     *
     * @example
     * ```hx
     * chacha20(&key, &nonce, 0, "abc", out[0..2]); // throws ChaCha20Error.ShortBuffer
     * ```
     *
     * @since 1.0.0
     */

    ShortBuffer,

    /**
     * The input needs a block counter past `0xFFFFFFFF`.
     *
     * @remarks
     * Each 64-byte block takes the next counter value, and RFC 8439 forbids letting the 32-bit counter wrap,
     * since a wrapped counter would repeat the key stream.
     * The last block may use `0xFFFFFFFF` itself.
     *
     * @example
     * ```hx
     * chacha20(&key, &nonce, 0xFFFFFFFF, &bytes65, &out); // throws ChaCha20Error.CounterOverflow
     * ```
     *
     * @since 1.0.0
     */

    CounterOverflow,
}
