/**
 * The errors that setting up AES can throw.
 *
 * @remarks
 * Only the key can be wrong, since encrypting a block always works once the round keys exist.
 *
 * @example
 * ```hx
 * Aes.init("short"); // throws AesError.BadKeyLength
 * ```
 *
 * @since 1.0.0
 */

export error AesError {
    /**
     * The key is not 16, 24, or 32 bytes long.
     *
     * @remarks
     * Those lengths select AES-128, AES-192, and AES-256, and FIPS 197 defines no others.
     * A password is not a key, so derive one with a key derivation function first.
     *
     * @example
     * ```hx
     * Aes.init("fifteen bytes!!"); // throws AesError.BadKeyLength
     * ```
     *
     * @since 1.0.0
     */

    BadKeyLength,
}
