/**
 * Exports
 */

export { HkdfError } from "@hkdf/errors/hkdf.error";

/**
 * Imports
 */

import { HmacSha256 } from "@hmac";
import { HkdfError } from "@hkdf/errors/hkdf.error";

/**
 * The size of one HMAC-SHA256 output in bytes, which is also the size of the pseudorandom key.
 *
 * @remarks
 * The expand step produces its output in blocks of this size and cuts the last one to fit.
 *
 * @since 1.0.0
 */

const HashLength: usize = 32;

/**
 * The most bytes that one expand step can produce, 255 blocks of {@link HashLength}.
 *
 * @remarks
 * RFC 5869 numbers the blocks with one byte that starts at 1, so 255 blocks is the limit.
 *
 * @since 1.0.0
 */

const MaxOutput: usize = 8160;

/**
 * Runs the extract step of HKDF-SHA256, which concentrates input key material into a pseudorandom key.
 *
 * @param salt - A non-secret random value, or an empty slice when there is none
 * @param ikm - The input key material, such as a Diffie-Hellman shared secret
 * @returns The 32-byte pseudorandom key
 *
 * @remarks
 * It is HMAC-SHA256 with the salt as the key and the input key material as the message, as RFC 5869 defines it.
 * An empty salt gives the same result as 32 zero bytes, which is the default that the RFC names,
 * since HMAC pads a short key with zeros anyway.
 * Skip this step and call {@link hkdfSha256Expand} directly only when the input is already a uniform random key.
 *
 * @example
 * ```hx
 * let ikm: u8[22] = undefined;
 * for (const _, i of ikm) ikm[i] = 0x0B;
 * hkdfSha256Extract("", &ikm); // "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
 * ```
 *
 * @since 1.0.0
 */

export function hkdfSha256Extract(salt: readonly u8[], ikm: readonly u8[]): u8[32] {
    let mac = HmacSha256.init(salt);
    mac.update(ikm);

    return mac.finish();
}

/**
 * Runs the expand step of HKDF-SHA256, which stretches a pseudorandom key into as many bytes as `out` holds.
 *
 * @param prk - The pseudorandom key, usually from {@link hkdfSha256Extract}
 * @param info - Context that binds the output to one purpose, such as a protocol label, or an empty slice
 * @param out - The buffer for the output key material, at most 8160 bytes
 * @returns `out`, filled with key material
 * @throws HkdfError.OutputTooLong when `out` is longer than 8160 bytes
 *
 * @remarks
 * Block `i` is the HMAC-SHA256 under `prk` of block `i - 1`, then `info`, then the byte `i`,
 * and the output is the blocks one after another, with the last one cut to fit.
 * It hashes the key once and copies the keyed MAC for each block, so a longer `prk` costs nothing extra per block.
 * Two calls that differ only in `info` give independent keys, so derive each key from its own label.
 * A shorter `out` gives a prefix of a longer one with the same inputs.
 *
 * @example
 * ```hx
 * const prk = hkdfSha256Extract("salt", "ikm");
 * let out: u8[32] = undefined;
 * try hkdfSha256Expand(&prk, "info", &out); // "fe8f9615d2374c0d17f77d1aeaf408c2e75fe0466073d0def23c733e2f862dfd"
 * ```
 *
 * @since 1.0.0
 */

export function hkdfSha256Expand(prk: readonly u8[], info: readonly u8[], out: u8[]): u8[] | Error {
    if (out.len > MaxOutput) throw HkdfError.OutputTooLong;
    const keyed = HmacSha256.init(prk);
    let block: u8[32] = undefined;
    let counter: u8[1] = [0];
    const blocks = (out.len + HashLength - 1) / HashLength;
    for (const i of 0..blocks) {
        let mac = keyed;
        if (i > 0) mac.update(&block);
        mac.update(info);
        counter[0] = (i + 1) as u8;
        mac.update(&counter);
        block = mac.finish();
        const offset = i * HashLength;
        const take = out.len - offset < HashLength ? out.len - offset : HashLength;
        for (const j of 0..take) out[offset + j] = block[j];
    }
    return out;
}

/**
 * Derives key material with HKDF-SHA256, running the extract and expand steps in one call.
 *
 * @param salt - A non-secret random value, or an empty slice when there is none
 * @param ikm - The input key material
 * @param info - Context that binds the output to one purpose, or an empty slice
 * @param out - The buffer for the output key material, at most 8160 bytes
 * @returns `out`, filled with key material
 * @throws HkdfError.OutputTooLong when `out` is longer than 8160 bytes
 *
 * @remarks
 * It is {@link hkdfSha256Extract} followed by {@link hkdfSha256Expand}.
 * Use the two steps when several keys come from one input, so the extract step runs once.
 * HKDF is for input that already has enough entropy, such as a shared secret.
 * For a password, use {@link pbkdf2Sha256} or {@link scrypt}, which are slow on purpose.
 *
 * @example
 * ```hx
 * let ikm: u8[22] = undefined;
 * for (const _, i of ikm) ikm[i] = 0x0B;
 * let out: u8[42] = undefined;
 * try hkdfSha256("", &ikm, "", &out); // "8da4e775...faa4b61a96c8", as RFC 5869 test case 3 gives
 * ```
 *
 * @see hkdfSha256Expand
 * @see hkdfSha256Extract
 *
 * @since 1.0.0
 */

export function hkdfSha256(salt: readonly u8[], ikm: readonly u8[], info: readonly u8[], out: u8[]): u8[] | Error {
    const prk = hkdfSha256Extract(salt, ikm);

    return try hkdfSha256Expand(&prk, info, out);
}
