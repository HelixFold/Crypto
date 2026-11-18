/**
 * The errors that PBKDF2-HMAC-SHA256 can throw.
 *
 * @remarks
 * PBKDF2 writes into a buffer that the caller passes,
 * so the errors cover only parameters that RFC 8018 does not allow.
 *
 * @example
 * ```hx
 * pbkdf2Sha256("password", "salt", 0, &out); // throws Pbkdf2Error.ZeroIterations
 * ```
 *
 * @since 1.0.0
 */

export error Pbkdf2Error {
    /**
     * The iteration count is zero.
     *
     * @remarks
     * Every block needs at least one HMAC, so RFC 8018 requires a count of 1 or more.
     * A count that low is only for building other functions such as scrypt.
     * Pick a count for a password that makes one derivation take as long as the system can afford.
     *
     * @example
     * ```hx
     * pbkdf2Sha256("password", "salt", 0, &out); // throws Pbkdf2Error.ZeroIterations
     * ```
     *
     * @since 1.0.0
     */

    ZeroIterations,

    /**
     * The output buffer asks for more than 2^32 - 1 blocks of 32 bytes.
     *
     * @remarks
     * The block index is a 32-bit number, so RFC 8018 caps the output at 137438953440 bytes.
     * Only a 64-bit target can even hold a buffer that large.
     *
     * @example
     * ```hx
     * pbkdf2Sha256("password", "salt", 1, huge); // throws Pbkdf2Error.OutputTooLong
     * ```
     *
     * @since 1.0.0
     */

    OutputTooLong,
}
