/**
 * Exports
 */

export { HmacSha256 } from "@hmac/structs/hmac.struct";

/**
 * Imports
 */

import { timingSafeEqual } from "@compare";
import { HmacSha256 } from "@hmac/structs/hmac.struct";

/**
 * Computes the HMAC-SHA256 of a message under a key.
 *
 * @param key - The secret key, of any length
 * @param bytes - The message
 * @returns The 32-byte tag
 *
 * @remarks
 * Use it when the whole message is at hand, and {@link HmacSha256} when it arrives in pieces.
 * To check a tag that someone sent, use {@link verifyHmacSha256} instead of comparing the result.
 *
 * @example
 * ```hx
 * hmacSha256("Jefe", "what do ya want for nothing?"); // the bytes 5bdcc146...64ec3843
 * ```
 *
 * @since 1.0.0
 */

export function hmacSha256(key: readonly u8[], bytes: readonly u8[]): u8[32] {
    let mac = HmacSha256.init(key);
    mac.update(bytes);

    return mac.finish();
}

/**
 * Tells whether a tag is the HMAC-SHA256 of a message under a key.
 *
 * @param key - The secret key
 * @param bytes - The message
 * @param tag - The tag to check
 * @returns `true` when the tag matches
 *
 * @remarks
 * It compares with {@link timingSafeEqual}, so its timing reveals nothing about the right tag.
 * A tag of any length other than 32 bytes never matches.
 *
 * @example
 * ```hx
 * const tag = hmacSha256("Jefe", "what do ya want for nothing?");
 * verifyHmacSha256("Jefe", "what do ya want for nothing?", &tag); // true
 * verifyHmacSha256("Jefe", "what do ya want for nothing!", &tag); // false
 * ```
 *
 * @since 1.0.0
 */

export function verifyHmacSha256(key: readonly u8[], bytes: readonly u8[], tag: readonly u8[]): bool {
    const expected = hmacSha256(key, bytes);

    return timingSafeEqual(&expected, tag);
}
