/**
 * The errors that HKDF-SHA256 can throw.
 *
 * @remarks
 * HKDF writes into a buffer that the caller passes,
 * so the only thing that can go wrong is asking for more key material than RFC 5869 allows.
 *
 * @example
 * ```hx
 * let out: u8[8161] = undefined;
 * hkdfSha256Expand(&prk, "", &out); // throws HkdfError.OutputTooLong
 * ```
 *
 * @since 1.0.0
 */

export error HkdfError {
    /**
     * The output buffer asks for more than 8160 bytes, which is 255 blocks of SHA-256.
     *
     * @remarks
     * The expand step numbers its blocks with a single byte, so RFC 5869 caps the output at 255 times 32 bytes.
     * Derive a longer stream from the result with a different `info` per piece instead.
     *
     * @example
     * ```hx
     * let out: u8[8161] = undefined;
     * hkdfSha256Expand(&prk, "", &out); // throws HkdfError.OutputTooLong
     * ```
     *
     * @since 1.0.0
     */

    OutputTooLong,
}
