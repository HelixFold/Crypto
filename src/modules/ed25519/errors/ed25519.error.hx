/**
 * The errors that Ed25519 key derivation and signing can throw.
 *
 * @remarks
 * Verification never throws, since a key or signature of the wrong length is simply not valid,
 * so it returns `false` instead.
 *
 * @example
 * ```hx
 * ed25519Sign(seed[0..31], "message"); // throws Ed25519Error.BadKeyLength
 * ```
 *
 * @since 1.0.0
 */

export error Ed25519Error {
    /**
     * The seed is not 32 bytes long.
     *
     * @remarks
     * An Ed25519 private key is a 32-byte seed in RFC 8032.
     * The 64-byte secret key of TweetNaCl and libsodium is the seed followed by the public key,
     * so pass its first 32 bytes.
     *
     * @example
     * ```hx
     * ed25519PublicKey(seed[0..31]); // throws Ed25519Error.BadKeyLength
     * ```
     *
     * @since 1.0.0
     */

    BadKeyLength,
}
