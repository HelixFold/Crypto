/**
 * Tells whether two byte strings are equal, in a time that doesn't depend on where they differ.
 *
 * @param a - The first bytes
 * @param b - The second bytes
 * @returns `true` when both have the same length and the same bytes
 *
 * @remarks
 * An ordinary comparison stops at the first difference,
 * so its timing tells an attacker how many leading bytes of a guess are right.
 * This one reads every byte and folds the differences together, so the time depends only on the length.
 * The length itself is not secret for a digest or a MAC tag, so a length mismatch returns at once.
 * Use it whenever one side is secret, as when checking a MAC tag or a password hash.
 *
 * @example
 * ```hx
 * timingSafeEqual("abc", "abc"); // true
 * timingSafeEqual("abc", "abd"); // false
 * timingSafeEqual("abc", "ab");  // false
 * ```
 *
 * @since 1.0.0
 */

export function timingSafeEqual(a: readonly u8[], b: readonly u8[]): bool {
    if (a.len != b.len) return false;
    let diff: u8 = 0;
    for (const byte, i of a) diff |= byte ^ b[i];
    return diff == 0;
}
