/**
 * The errors that scrypt throws for parameters that RFC 7914 does not allow.
 *
 * @remarks
 * Every check runs before scrypt allocates anything, so a bad parameter never costs memory.
 * An allocator that runs out of memory throws its own error instead,
 * and the final PBKDF2 step passes on {@link Pbkdf2Error.OutputTooLong} for an oversized output.
 *
 * @example
 * ```hx
 * scrypt(allocator, "pw", "salt", 1000, 8, 1, &out); // throws ScryptError.BadCost
 * ```
 *
 * @since 1.0.0
 */

export error ScryptError {
    /**
     * The cost `n` is not a power of two greater than 1, or it is too large for the block size.
     *
     * @remarks
     * ROMix reduces an index modulo `n` with a mask, which only works for a power of two.
     * RFC 7914 also requires `n` to be below 2 to the power of `16 * r`,
     * so with `r` of 1 the largest cost is 32768.
     *
     * @example
     * ```hx
     * scrypt(allocator, "pw", "salt", 1000, 8, 1, &out); // throws ScryptError.BadCost
     * scrypt(allocator, "pw", "salt", 1, 8, 1, &out);    // throws ScryptError.BadCost
     * ```
     *
     * @since 1.0.0
     */

    BadCost,

    /**
     * The block size `r` is zero.
     *
     * @remarks
     * Each block holds `2 * r` Salsa20/8 blocks of 64 bytes, so `r` must be at least 1.
     *
     * @example
     * ```hx
     * scrypt(allocator, "pw", "salt", 16, 0, 1, &out); // throws ScryptError.BadBlockSize
     * ```
     *
     * @since 1.0.0
     */

    BadBlockSize,

    /**
     * The parallelism `p` is zero, or `p * r` reaches 2^30.
     *
     * @remarks
     * RFC 7914 bounds `p * r` so that the first PBKDF2 step stays within its output limit.
     *
     * @example
     * ```hx
     * scrypt(allocator, "pw", "salt", 16, 1, 0, &out); // throws ScryptError.BadParallelism
     * ```
     *
     * @since 1.0.0
     */

    BadParallelism,

    /**
     * The memory that `n`, `r`, and `p` need does not fit in a `usize`.
     *
     * @remarks
     * ROMix needs `128 * r * n` bytes and the first step needs `128 * r * p` bytes.
     * On a 32-bit target this error arrives long before the parameters reach the limits of RFC 7914.
     *
     * @example
     * ```hx
     * scrypt(allocator, "pw", "salt", 1 << 40, 1 << 20, 1, &out); // throws ScryptError.TooMuchMemory
     * ```
     *
     * @since 1.0.0
     */

    TooMuchMemory,
}
