/**
 * The errors that Poly1305 can throw.
 *
 * @remarks
 * Only the key can be wrong, since a message of any length is valid.
 *
 * @example
 * ```hx
 * Poly1305.init("short"); // throws Poly1305Error.BadKeyLength
 * ```
 *
 * @since 1.0.0
 */

export error Poly1305Error {
    /**
     * The key is not exactly 32 bytes long.
     *
     * @remarks
     * The first 16 bytes are the evaluation point `r` and the last 16 are the final addend `s`,
     * so neither half can be shorter.
     *
     * @example
     * ```hx
     * poly1305("short", "message"); // throws Poly1305Error.BadKeyLength
     * ```
     *
     * @since 1.0.0
     */

    BadKeyLength,
}
