/**
 * Exports
 */

export { AeadError } from "@aead/errors/aead.error";

/**
 * Imports
 */

import { timingSafeEqual } from "@compare";
import { Poly1305 } from "@poly1305";
import { chacha20, chacha20Block } from "@chacha20";
import { AeadError } from "@aead/errors/aead.error";

/**
 * The longest message that one nonce can encrypt, in bytes.
 *
 * @remarks
 * The message starts at block counter 1, and the 32-bit counter must not wrap,
 * so it holds at most `0xFFFFFFFF` blocks of 64 bytes.
 *
 * @since 1.0.0
 */

const MaxLength: u64 = 274_877_906_880;

/**
 * Checks the key, the nonce, and the lengths of a seal or an open.
 *
 * @param key - The key
 * @param nonce - The nonce
 * @param input - The plaintext or the ciphertext
 * @param out - The output buffer
 * @throws AeadError.BadKeyLength when the key is not 32 bytes
 * @throws AeadError.BadNonceLength when the nonce is not 12 bytes
 * @throws AeadError.TooLong when the input is longer than {@link MaxLength}
 * @throws AeadError.ShortBuffer when `out` is shorter than the input
 *
 * @remarks
 * Running every check first means that no later step can fail with a ChaCha20 error,
 * and an error never leaves partial output behind.
 *
 * @since 1.0.0
 */

function check(key: readonly u8[], nonce: readonly u8[], input: readonly u8[], out: u8[]): void | Error {
    if (key.len != 32) throw AeadError.BadKeyLength;
    if (nonce.len != 12) throw AeadError.BadNonceLength;
    if (input.len as u64 > MaxLength) throw AeadError.TooLong;
    if (out.len < input.len) throw AeadError.ShortBuffer;
}

/**
 * Writes a 64-bit length as eight little-endian bytes.
 *
 * @param out - The buffer
 * @param at - The index of the lowest byte
 * @param value - The length
 *
 * @remarks
 * The last block of the Poly1305 input holds the two lengths in this form.
 *
 * @since 1.0.0
 */

function store64(out: u8[], at: usize, value: u64): void {
    for (const i of 0..8) out[at + i] = @truncate(u8, value >> (8 * i as u64));
}

/**
 * Computes the tag of a ChaCha20-Poly1305 message.
 *
 * @param key - The 32-byte key
 * @param nonce - The 12-byte nonce
 * @param aad - The associated data
 * @param ciphertext - The ciphertext
 * @returns The 16-byte tag
 *
 * @remarks
 * It follows section 2.8 of RFC 8439.
 * The one-time Poly1305 key is the first 32 bytes of the ChaCha20 block at counter 0.
 * The MAC then takes the associated data, zeros up to a multiple of 16,
 * the ciphertext, zeros up to a multiple of 16, and both lengths as 64-bit little-endian numbers.
 * The caller has already checked the key and the nonce, so the inner calls can't fail.
 *
 * @since 1.0.0
 */

function authenticate(
    key: readonly u8[], nonce: readonly u8[], aad: readonly u8[], ciphertext: readonly u8[],
): u8[16] | Error {
    const stream = try chacha20Block(key, nonce, 0);
    let mac = try Poly1305.init(stream[0..32]);

    let zeros: u8[16] = undefined;
    for (const _, i of zeros) zeros[i] = 0;
    mac.update(aad);
    mac.update(zeros[0..(16 - (aad.len % 16)) % 16]);
    mac.update(ciphertext);
    mac.update(zeros[0..(16 - (ciphertext.len % 16)) % 16]);

    let lengths: u8[16] = undefined;
    store64(&lengths, 0, aad.len as u64);
    store64(&lengths, 8, ciphertext.len as u64);
    mac.update(&lengths);

    return mac.finish();
}

/**
 * Encrypts and authenticates a message with ChaCha20-Poly1305.
 *
 * @param key - The 32-byte secret key
 * @param nonce - The 12-byte nonce, which must never repeat under the same key
 * @param aad - The associated data, which the tag covers but which stays unencrypted
 * @param plaintext - The message
 * @param out - The buffer for the ciphertext, at least as long as `plaintext`
 * @returns The 16-byte tag, which the receiver needs along with the ciphertext
 * @throws AeadError.BadKeyLength when the key is not 32 bytes
 * @throws AeadError.BadNonceLength when the nonce is not 12 bytes
 * @throws AeadError.TooLong when the plaintext is longer than 274,877,906,880 bytes
 * @throws AeadError.ShortBuffer when `out` is shorter than `plaintext`
 *
 * @remarks
 * It's the AEAD construction of section 2.8 of RFC 8439.
 * The ciphertext fills the start of `out`, as many bytes as the plaintext has, and the tag comes back separately.
 * Never reuse a nonce with the same key.
 * A repeated nonce reveals the XOR of the two plaintexts and the Poly1305 key, which lets anyone forge tags.
 * A counter or 12 random bytes per message both work as nonces.
 * Associated data is for headers that must arrive unchanged but need no secrecy, and it may be empty.
 * `out` may be the same buffer as `plaintext`.
 *
 * @example
 * ```hx
 * let ciphertext: u8[3] = undefined;
 * const tag = try chacha20Poly1305Seal(&key, &nonce, "header", "abc", &ciphertext);
 * let plain: u8[3] = undefined;
 * try chacha20Poly1305Open(&key, &nonce, "header", &ciphertext, &tag, &plain); // "abc"
 * ```
 *
 * @since 1.0.0
 */

export function chacha20Poly1305Seal(
    key: readonly u8[], nonce: readonly u8[], aad: readonly u8[], plaintext: readonly u8[], out: u8[],
): u8[16] | Error {
    try check(key, nonce, plaintext, out);
    const ciphertext = try chacha20(key, nonce, 1, plaintext, out);

    return try authenticate(key, nonce, aad, ciphertext);
}

/**
 * Checks and decrypts a message sealed with ChaCha20-Poly1305.
 *
 * @param key - The 32-byte secret key
 * @param nonce - The 12-byte nonce that the message was sealed with
 * @param aad - The associated data that the message was sealed with
 * @param ciphertext - The ciphertext
 * @param tag - The 16-byte tag from {@link chacha20Poly1305Seal}
 * @param out - The buffer for the plaintext, at least as long as `ciphertext`
 * @returns The part of `out` that holds the plaintext
 * @throws AeadError.BadKeyLength when the key is not 32 bytes
 * @throws AeadError.BadNonceLength when the nonce is not 12 bytes
 * @throws AeadError.TooLong when the ciphertext is longer than 274,877,906,880 bytes
 * @throws AeadError.ShortBuffer when `out` is shorter than `ciphertext`
 * @throws AeadError.BadTag when the tag doesn't match
 *
 * @remarks
 * It computes the tag of the ciphertext and compares it with {@link timingSafeEqual} before decrypting,
 * so a forged or damaged message never releases any plaintext, and `out` stays as it was.
 * Treat {@link AeadError.BadTag} as an attack or a transmission error, never as a partial success.
 * `out` may be the same buffer as `ciphertext`.
 *
 * @example
 * ```hx
 * let plain: u8[3] = undefined;
 * try chacha20Poly1305Open(&key, &nonce, "header", &ciphertext, &tag, &plain); // "abc"
 * tag[0] ^= 1;
 * chacha20Poly1305Open(&key, &nonce, "header", &ciphertext, &tag, &plain); // throws AeadError.BadTag
 * ```
 *
 * @since 1.0.0
 */

export function chacha20Poly1305Open(
    key: readonly u8[], nonce: readonly u8[], aad: readonly u8[], ciphertext: readonly u8[], tag: readonly u8[],
    out: u8[],
): u8[] | Error {
    try check(key, nonce, ciphertext, out);
    const expected = try authenticate(key, nonce, aad, ciphertext);
    if (!timingSafeEqual(&expected, tag)) throw AeadError.BadTag;

    return try chacha20(key, nonce, 1, ciphertext, out);
}
