/**
 * Exports
 */

export { Ed25519Error } from "@ed25519/errors/ed25519.error";

/**
 * Imports
 */

import { Sha512 } from "@sha512";
import { Ed25519Error } from "@ed25519/errors/ed25519.error";
import { isCanonicalScalar, modOrder, reduceScalar } from "@ed25519/components/scalar.component";
import { packPoint, pointAdd, scalarMult, scalarMultBase, unpackNegative } from "@ed25519/components/point.component";

/**
 * Hashes a seed into the clamped secret scalar and the nonce prefix.
 *
 * @param seed - The 32-byte seed
 * @returns The SHA-512 of the seed, with its first 32 bytes clamped into the secret scalar
 *
 * @remarks
 * RFC 8032 section 5.1.5 clears the low 3 bits and bit 255 of the first half and sets bit 254.
 * The second half stays as it is and becomes the prefix that the nonce hash starts with.
 * The caller checks the length of the seed first.
 *
 * @since 1.0.0
 */

function expandSeed(seed: readonly u8[]): u8[64] {
    let hash = Sha512.init();
    hash.update(seed);
    let d = hash.finish();
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    return d;
}

/**
 * Derives the Ed25519 public key of a 32-byte seed.
 *
 * @param seed - The 32-byte private seed
 * @returns The 32-byte public key, the compressed point A
 * @throws Ed25519Error.BadKeyLength when `seed` is not 32 bytes long
 *
 * @remarks
 * It hashes the seed with SHA-512, clamps the first half into the secret scalar,
 * and multiplies the base point by it, as RFC 8032 section 5.1.5 describes.
 * The multiplication runs in constant time, so the timing does not depend on the seed.
 * The package has no random source, so the caller must draw the seed from a cryptographic one,
 * as 32 uniformly random bytes, and keep it secret.
 *
 * @example
 * ```hx
 * try ed25519PublicKey(&seed); // "d75a9801...f707511a" for the seed of RFC 8032 TEST 1
 * ```
 *
 * @see ed25519Sign
 * @since 1.0.0
 */

export function ed25519PublicKey(seed: readonly u8[]): u8[32] | Error {
    if (seed.len != 32) throw Ed25519Error.BadKeyLength;
    const d = expandSeed(seed);
    return packPoint(scalarMultBase(d[0..32]));
}

/**
 * Signs a message with Ed25519 under a 32-byte seed.
 *
 * @param seed - The 32-byte private seed
 * @param message - The message, of any length
 * @returns The 64-byte signature, the point R followed by the scalar S
 * @throws Ed25519Error.BadKeyLength when `seed` is not 32 bytes long
 *
 * @remarks
 * It follows `crypto_sign` of TweetNaCl and pure Ed25519 of RFC 8032 section 5.1.6.
 * The nonce r is the SHA-512 of the seed's prefix and the message, reduced modulo L,
 * so the same seed and message always give the same signature, and no randomness is needed to sign.
 * S is r plus the challenge hash times the secret scalar, reduced modulo L.
 * The public key is derived again from the seed on every call, so the caller cannot pass a mismatched one.
 * The scalar multiplications, the packing, and the reduction run in constant time,
 * so neither the branches nor the memory accesses depend on the seed.
 * The package has no random source, so the caller must draw the seed from a cryptographic one.
 *
 * @example
 * ```hx
 * const signature = try ed25519Sign(&seed, "\x72"); // "92a009a9...12bb0c00" for RFC 8032 TEST 2
 * ed25519Verify(&publicKey, "\x72", &signature);    // true
 * ```
 *
 * @see ed25519Verify
 * @since 1.0.0
 */

export function ed25519Sign(seed: readonly u8[], message: readonly u8[]): u8[64] | Error {
    if (seed.len != 32) throw Ed25519Error.BadKeyLength;
    const d = expandSeed(seed);
    const publicKey = packPoint(scalarMultBase(d[0..32]));

    let nonceHash = Sha512.init();
    nonceHash.update(d[32..64]);
    nonceHash.update(message);
    const nonceDigest = nonceHash.finish();
    const r = reduceScalar(&nonceDigest);
    const commitment = packPoint(scalarMultBase(&r));

    let challengeHash = Sha512.init();
    challengeHash.update(&commitment);
    challengeHash.update(&publicKey);
    challengeHash.update(message);
    const challengeDigest = challengeHash.finish();
    const h = reduceScalar(&challengeDigest);

    let x: i64[64] = undefined;
    for (const i of 0..64) x[i] = 0;
    for (const i of 0..32) x[i] = r[i] as i64;
    for (const i of 0..32) {
        for (const j of 0..32) x[i + j] += (h[i] as i64) * (d[j] as i64);
    }
    const s = modOrder(&x);

    let signature: u8[64] = undefined;
    for (const i of 0..32) {
        signature[i] = commitment[i];
        signature[32 + i] = s[i];
    }
    return signature;
}

/**
 * Tells whether a signature is a valid Ed25519 signature of a message under a public key.
 *
 * @param publicKey - The 32-byte public key
 * @param message - The message, of any length
 * @param signature - The 64-byte signature
 * @returns `true` when the signature is valid
 *
 * @remarks
 * It follows `crypto_sign_open` of TweetNaCl and pure Ed25519 of RFC 8032 section 5.1.7.
 * It returns `false` for a public key or signature of the wrong length,
 * for an S of L or more, and for a public key that doesn't decode as RFC 8032 section 5.1.3 describes.
 * It checks that S * B - h * A encodes to the R of the signature,
 * so an R that is not a canonical encoding never matches.
 * It checks the equation without the cofactor 8, as TweetNaCl and OpenSSL do.
 * Every input is public, so verification makes no promise about timing.
 *
 * @example
 * ```hx
 * ed25519Verify(&publicKey, "\xaf\x82", &signature); // true for RFC 8032 TEST 3
 * ed25519Verify(&publicKey, "\xaf\x83", &signature); // false, since the message changed
 * ```
 *
 * @see ed25519Sign
 * @since 1.0.0
 */

export function ed25519Verify(publicKey: readonly u8[], message: readonly u8[], signature: readonly u8[]): bool {
    if (publicKey.len != 32 || signature.len != 64) return false;
    if (!isCanonicalScalar(signature[32..64])) return false;
    if (const negativeA = unpackNegative(publicKey)) {
        let hash = Sha512.init();
        hash.update(signature[0..32]);
        hash.update(publicKey);
        hash.update(message);
        const digest = hash.finish();
        const h = reduceScalar(&digest);

        const check = packPoint(pointAdd(scalarMult(negativeA, &h), scalarMultBase(signature[32..64])));
        let diff: u8 = 0;
        for (const i of 0..32) diff |= check[i] ^ signature[i];
        return diff == 0;
    }
    return false;
}
