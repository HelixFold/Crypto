/**
 * Exports
 */

export { Pbkdf2Error } from "@pbkdf2/errors/pbkdf2.error";

/**
 * Imports
 */

import { HmacSha256 } from "@hmac";
import { Pbkdf2Error } from "@pbkdf2/errors/pbkdf2.error";

/**
 * The size of one HMAC-SHA256 output in bytes, which is the size of one PBKDF2 block.
 *
 * @remarks
 * The output is built from blocks of this size, with the last one cut to fit.
 *
 * @since 1.0.0
 */

const BlockLength: usize = 32;

/**
 * The most bytes that PBKDF2-HMAC-SHA256 can produce, 2^32 - 1 blocks of {@link BlockLength}.
 *
 * @remarks
 * RFC 8018 numbers the blocks with a 32-bit big-endian index that starts at 1.
 * It is a `u64` so that the comparison also works where `usize` has 32 bits.
 *
 * @since 1.0.0
 */

const MaxOutput: u64 = 137438953440;

/**
 * Derives key material from a password with PBKDF2-HMAC-SHA256.
 *
 * @param password - The password, used as the HMAC key
 * @param salt - A random value unique to this password, 16 bytes or more
 * @param iterations - How many HMACs each 32-byte block costs, at least 1
 * @param out - The buffer for the derived key, of any length
 * @returns `out`, filled with the derived key
 * @throws Pbkdf2Error.ZeroIterations when `iterations` is 0
 * @throws Pbkdf2Error.OutputTooLong when `out` is longer than 2^32 - 1 blocks
 *
 * @remarks
 * It follows RFC 8018: block `i` is the XOR of `U1` to `Uc`,
 * where `U1` is the HMAC of the salt and the index `i`, and each later `U` is the HMAC of the one before.
 * It keys {@link HmacSha256} once and copies the keyed struct for every HMAC,
 * so the password is hashed into the pads once rather than once per iteration.
 * Every iteration does the same work whatever the password is, without branches or table lookups on secret bytes.
 * Each block costs `iterations` HMACs, so an output longer than 32 bytes multiplies the work for the caller
 * and not for an attacker, who needs only the first block to test a guess.
 * Prefer {@link scrypt} where memory is available, since it also resists attacks with custom hardware.
 *
 * @example
 * ```hx
 * let out: u8[32] = undefined;
 * try pbkdf2Sha256("password", "salt", 4096, &out); // "c5e478d5...aa98134a"
 * ```
 *
 * @since 1.0.0
 */

export function pbkdf2Sha256(password: readonly u8[], salt: readonly u8[], iterations: u32, out: u8[]): u8[] | Error {
    if (iterations == 0) throw Pbkdf2Error.ZeroIterations;
    if (out.len as u64 > MaxOutput) throw Pbkdf2Error.OutputTooLong;
    const keyed = HmacSha256.init(password);
    const rounds = iterations as usize;
    let index: u8[4] = undefined;
    let u: u8[32] = undefined;
    let t: u8[32] = undefined;
    const blocks = (out.len + BlockLength - 1) / BlockLength;
    for (const b of 0..blocks) {
        const number = (b + 1) as u32;
        index[0] = (number >> 24) as u8;
        index[1] = ((number >> 16) & 0xFF) as u8;
        index[2] = ((number >> 8) & 0xFF) as u8;
        index[3] = (number & 0xFF) as u8;
        let first = keyed;
        first.update(salt);
        first.update(&index);
        u = first.finish();
        t = u;
        for (const _ of 1..rounds) {
            let mac = keyed;
            mac.update(&u);
            u = mac.finish();
            for (const k of 0..BlockLength) t[k] ^= u[k];
        }
        const offset = b * BlockLength;
        const take = out.len - offset < BlockLength ? out.len - offset : BlockLength;
        for (const k of 0..take) out[offset + k] = t[k];
    }
    return out;
}
