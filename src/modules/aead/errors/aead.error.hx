/**
 * The errors that sealing or opening a message with an AEAD can throw.
 *
 * @remarks
 * ChaCha20-Poly1305 and AES-GCM share these errors, so a caller handles both the same way.
 * Every length check runs before any output is written,
 * and opening checks the tag before it decrypts anything.
 *
 * @example
 * ```hx
 * chacha20Poly1305Open(&key, &nonce, "", &ciphertext, &badTag, &out); // throws AeadError.BadTag
 * ```
 *
 * @since 1.0.0
 */

export error AeadError {
    /**
     * The key has a length that the cipher doesn't take.
     *
     * @remarks
     * ChaCha20-Poly1305 takes 32 bytes, and AES-GCM takes 16, 24, or 32 bytes.
     *
     * @example
     * ```hx
     * chacha20Poly1305Seal("short", &nonce, "", "", &out); // throws AeadError.BadKeyLength
     * ```
     *
     * @since 1.0.0
     */

    BadKeyLength,

    /**
     * The nonce is not exactly 12 bytes long.
     *
     * @remarks
     * Both ciphers here take the 96-bit nonce of RFC 8439 and of GCM's fast path, and nothing else.
     *
     * @example
     * ```hx
     * aesGcmSeal(&key, "8 bytes!", "", "", &out); // throws AeadError.BadNonceLength
     * ```
     *
     * @since 1.0.0
     */

    BadNonceLength,

    /**
     * The output buffer is shorter than the plaintext or the ciphertext.
     *
     * @remarks
     * The ciphertext is as long as the plaintext, and the tag comes back separately,
     * so `out` needs exactly the length of the input.
     *
     * @example
     * ```hx
     * chacha20Poly1305Seal(&key, &nonce, "", "abc", out[0..2]); // throws AeadError.ShortBuffer
     * ```
     *
     * @since 1.0.0
     */

    ShortBuffer,

    /**
     * The message is longer than one nonce can safely encrypt.
     *
     * @remarks
     * ChaCha20-Poly1305 stops at 274,877,906,880 bytes, about 256 GiB,
     * and AES-GCM stops at 68,719,476,704 bytes, about 64 GiB, where the 32-bit block counter would wrap.
     *
     * @example
     * ```hx
     * aesGcmSeal(&key, &nonce, "", &huge, &out); // throws AeadError.TooLong
     * ```
     *
     * @since 1.0.0
     */

    TooLong,

    /**
     * The tag doesn't match the ciphertext, the associated data, the key, and the nonce.
     *
     * @remarks
     * Something changed the message, or the wrong key or nonce was used.
     * The output buffer holds no plaintext when this is thrown,
     * since the tag is checked before anything is decrypted.
     * A tag of any length other than 16 bytes never matches.
     *
     * @example
     * ```hx
     * aesGcmOpen(&key, &nonce, "", &ciphertext, &badTag, &out); // throws AeadError.BadTag
     * ```
     *
     * @since 1.0.0
     */

    BadTag,
}
