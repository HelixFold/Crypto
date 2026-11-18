/**
 * Imports
 */

import { Sha256 } from "@sha256";

/**
 * The block size of SHA-256 in bytes, which HMAC pads the key to.
 *
 * @remarks
 * A key longer than this is hashed first, and a shorter one is padded with zeros.
 *
 * @since 1.0.0
 */

const BlockSize: usize = 64;

/**
 * A running HMAC-SHA256 that takes its message in pieces.
 *
 * @remarks
 * It follows RFC 2104 with SHA-256 from {@link Sha256}.
 * {@link HmacSha256.init} hashes the key's inner and outer pads once,
 * so the message is the only per-byte work.
 * Reach for it over {@link hmacSha256} when the message arrives in chunks.
 * Check a tag with {@link timingSafeEqual}, never with an ordinary comparison.
 *
 * @example
 * ```hx
 * let mac = HmacSha256.init("Jefe");
 * mac.update("what do ya want ");
 * mac.update("for nothing?");
 * mac.finish(); // the bytes 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
 * ```
 *
 * @since 1.0.0
 */

export struct HmacSha256 {
    /**
     * The inner hash, which has taken the key XOR `0x36` and then the message.
     *
     * @remarks
     * {@link HmacSha256.update} feeds the message here.
     *
     * @example
     * ```hx
     * mac.inner; // Sha256 { ... }
     * ```
     *
     * @since 1.0.0
     */

    inner: Sha256,

    /**
     * The outer hash, which has taken the key XOR `0x5C` and waits for the inner digest.
     *
     * @remarks
     * {@link HmacSha256.finish} works on a copy, so the field keeps its state.
     *
     * @example
     * ```hx
     * mac.outer; // Sha256 { ... }
     * ```
     *
     * @since 1.0.0
     */

    outer: Sha256,

    /**
     * Starts an HMAC-SHA256 under a key.
     *
     * @param key - The secret key, of any length
     * @returns The MAC, ready for the message
     *
     * @remarks
     * A key longer than 64 bytes is replaced by its SHA-256, as RFC 2104 says.
     * A key of 32 random bytes or more gives the full strength of SHA-256.
     *
     * @example
     * ```hx
     * HmacSha256.init("key").finish(); // the MAC of an empty message
     * ```
     *
     * @since 1.0.0
     */

    init(key: readonly u8[]): HmacSha256 {
        let block: u8[64] = undefined;
        for (const _, i of block) block[i] = 0;
        if (key.len > BlockSize) {
            let hasher = Sha256.init();
            hasher.update(key);
            const digest = hasher.finish();
            for (const byte, i of digest) block[i] = byte;
        } else {
            for (const byte, i of key) block[i] = byte;
        }

        let pad: u8[64] = undefined;
        for (const byte, i of block) pad[i] = byte ^ 0x36;
        let inner = Sha256.init();
        inner.update(&pad);
        for (const byte, i of block) pad[i] = byte ^ 0x5C;
        let outer = Sha256.init();
        outer.update(&pad);

        return HmacSha256 { inner, outer };
    }

    /**
     * Adds message bytes.
     *
     * @param bytes - The next bytes of the message
     *
     * @remarks
     * Splitting the message at any point gives the same MAC as adding it at once.
     *
     * @example
     * ```hx
     * let mac = HmacSha256.init("Jefe");
     * mac.update("what do ya want for nothing?");
     * mac.finish(); // the bytes 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
     * ```
     *
     * @since 1.0.0
     */

    update(this: *HmacSha256, bytes: readonly u8[]): void {
        this.inner.update(bytes);
    }

    /**
     * Tells the MAC of the message so far.
     *
     * @returns The 32-byte tag
     *
     * @remarks
     * It finishes copies of both hashes, so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let mac = HmacSha256.init("Jefe");
     * mac.update("what do ya want for nothing?");
     * mac.finish(); // the bytes 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *HmacSha256): u8[32] {
        const inner = this.inner;
        const digest = inner.finish();
        let outer = this.outer;
        outer.update(&digest);

        return outer.finish();
    }
}
