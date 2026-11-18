/**
 * Exports
 */

export { Keccak } from "@sha3/structs/keccak.struct";
export { Sha3x224, Sha3x256, Sha3x384, Sha3x512, Shake128, Shake256, ShakeReader } from "@sha3/structs/sha3.struct";

/**
 * Imports
 */

import { Sha3x224, Sha3x256, Sha3x384, Sha3x512, Shake128, Shake256 } from "@sha3/structs/sha3.struct";

/**
 * Computes the SHA3-224 digest of bytes.
 *
 * @param bytes - The bytes
 * @returns Their 28-byte digest
 *
 * @remarks
 * It's the SHA3-224 of FIPS 202, which differs from the original Keccak submission in its padding.
 * Use it when all the bytes are at hand, and {@link Sha3x224} when they arrive in pieces.
 *
 * @example
 * ```hx
 * const digest = sha3x224("abc");
 * let out: u8[56] = undefined;
 * try encodeHex(&digest, &out); // "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
 * ```
 *
 * @since 1.0.0
 */

export function sha3x224(bytes: readonly u8[]): u8[28] {
    let hash = Sha3x224.init();
    hash.update(bytes);

    return hash.finish();
}

/**
 * Computes the SHA3-256 digest of bytes.
 *
 * @param bytes - The bytes
 * @returns Their 32-byte digest
 *
 * @remarks
 * It's the SHA3-256 of FIPS 202, which differs from the original Keccak submission in its padding.
 * Use it when all the bytes are at hand, and {@link Sha3x256} when they arrive in pieces.
 *
 * @example
 * ```hx
 * const digest = sha3x256("abc");
 * let out: u8[64] = undefined;
 * try encodeHex(&digest, &out); // "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
 * ```
 *
 * @since 1.0.0
 */

export function sha3x256(bytes: readonly u8[]): u8[32] {
    let hash = Sha3x256.init();
    hash.update(bytes);

    return hash.finish();
}

/**
 * Computes the SHA3-384 digest of bytes.
 *
 * @param bytes - The bytes
 * @returns Their 48-byte digest
 *
 * @remarks
 * It's the SHA3-384 of FIPS 202, which differs from the original Keccak submission in its padding.
 * Use it when all the bytes are at hand, and {@link Sha3x384} when they arrive in pieces.
 *
 * @example
 * ```hx
 * const digest = sha3x384("abc");
 * let out: u8[96] = undefined;
 * try encodeHex(&digest, &out); // "ec01498288516fc9...39f1edf228376d25"
 * ```
 *
 * @since 1.0.0
 */

export function sha3x384(bytes: readonly u8[]): u8[48] {
    let hash = Sha3x384.init();
    hash.update(bytes);

    return hash.finish();
}

/**
 * Computes the SHA3-512 digest of bytes.
 *
 * @param bytes - The bytes
 * @returns Their 64-byte digest
 *
 * @remarks
 * It's the SHA3-512 of FIPS 202, which differs from the original Keccak submission in its padding.
 * Use it when all the bytes are at hand, and {@link Sha3x512} when they arrive in pieces.
 *
 * @example
 * ```hx
 * const digest = sha3x512("abc");
 * let out: u8[128] = undefined;
 * try encodeHex(&digest, &out); // "b751850b1a57168a...6592f8274eec53f0"
 * ```
 *
 * @since 1.0.0
 */

export function sha3x512(bytes: readonly u8[]): u8[64] {
    let hash = Sha3x512.init();
    hash.update(bytes);

    return hash.finish();
}

/**
 * Fills a buffer with the SHAKE128 output of bytes.
 *
 * @param bytes - The bytes
 * @param out - The buffer to fill, of any length
 *
 * @remarks
 * The output of a shorter buffer is the start of the output of a longer one.
 * Use it when all the bytes are at hand and the output fits one buffer,
 * and {@link Shake128} when either arrives in pieces.
 *
 * @example
 * ```hx
 * let digest: u8[32] = undefined;
 * shake128("abc", &digest);
 * let out: u8[64] = undefined;
 * try encodeHex(&digest, &out); // "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
 * ```
 *
 * @since 1.0.0
 */

export function shake128(bytes: readonly u8[], out: u8[]): void {
    let hash = Shake128.init();
    hash.update(bytes);
    let reader = hash.finish();
    reader.squeeze(out);
}

/**
 * Fills a buffer with the SHAKE256 output of bytes.
 *
 * @param bytes - The bytes
 * @param out - The buffer to fill, of any length
 *
 * @remarks
 * The output of a shorter buffer is the start of the output of a longer one.
 * Use it when all the bytes are at hand and the output fits one buffer,
 * and {@link Shake256} when either arrives in pieces.
 *
 * @example
 * ```hx
 * let digest: u8[32] = undefined;
 * shake256("abc", &digest);
 * let out: u8[64] = undefined;
 * try encodeHex(&digest, &out); // "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
 * ```
 *
 * @since 1.0.0
 */

export function shake256(bytes: readonly u8[], out: u8[]): void {
    let hash = Shake256.init();
    hash.update(bytes);
    let reader = hash.finish();
    reader.squeeze(out);
}
