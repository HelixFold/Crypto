/**
 * The errors that X25519 can throw.
 *
 * @remarks
 * Both functions take slices and check the length at runtime,
 * and the shared secret of a point of small order is an error rather than a key of all zeros.
 *
 * @example
 * ```hx
 * x25519(&scalar, &zero); // throws X25519Error.LowOrderPoint
 * ```
 *
 * @since 1.0.0
 */

export error X25519Error {
    /**
     * The scalar or the point is not 32 bytes long.
     *
     * @remarks
     * X25519 takes exactly 32 bytes for each, so a key from another curve or a truncated buffer fails here.
     *
     * @example
     * ```hx
     * x25519(scalar[0..31], &point); // throws X25519Error.BadKeyLength
     * ```
     *
     * @since 1.0.0
     */

    BadKeyLength,

    /**
     * The shared secret came out as 32 zero bytes, because the point has a small order.
     *
     * @remarks
     * A point whose order divides the cofactor 8 sends every scalar to the same output,
     * so a peer that sends one would force a secret it already knows.
     * RFC 7748 section 6.1 allows the check, and {@link x25519} always makes it by ORing the output bytes together.
     *
     * @example
     * ```hx
     * x25519(&scalar, &zero); // throws X25519Error.LowOrderPoint
     * ```
     *
     * @since 1.0.0
     */

    LowOrderPoint,
}
