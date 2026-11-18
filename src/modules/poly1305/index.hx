/**
 * Exports
 */

export { Poly1305 } from "@poly1305/structs/poly1305.struct";
export { Poly1305Error } from "@poly1305/errors/poly1305.error";

/**
 * Imports
 */

import { Poly1305 } from "@poly1305/structs/poly1305.struct";

/**
 * Computes the Poly1305 tag of a message under a one-time key.
 *
 * @param key - The 32-byte one-time key
 * @param bytes - The message
 * @returns The 16-byte tag
 * @throws Poly1305Error.BadKeyLength when the key is not 32 bytes
 *
 * @remarks
 * Poly1305 alone is a one-time authenticator: a key must never authenticate more than one message.
 * Use it when the whole message is at hand, and {@link Poly1305} when it arrives in pieces.
 * Most callers want {@link chacha20Poly1305Seal}, which derives a fresh key for every nonce.
 * Check a tag with {@link timingSafeEqual}, never with an ordinary comparison.
 *
 * @example
 * ```hx
 * // the key 85d6be78...4149f51b of RFC 8439, section 2.5.2
 * try poly1305(&key, "Cryptographic Forum Research Group"); // a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9
 * ```
 *
 * @since 1.0.0
 */

export function poly1305(key: readonly u8[], bytes: readonly u8[]): u8[16] | Error {
    let mac = try Poly1305.init(key);
    mac.update(bytes);

    return mac.finish();
}
