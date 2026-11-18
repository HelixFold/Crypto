/**
 * Imports
 */

import { Aes } from "@aes";
import { AeadError } from "@aead";
import { timingSafeEqual } from "@compare";

/**
 * The longest message that one nonce can encrypt, in bytes.
 *
 * @remarks
 * The message starts at counter 2 of the 32-bit block counter, which must not wrap,
 * so it holds at most `0xFFFFFFFE` blocks of 16 bytes, as NIST SP 800-38D allows.
 *
 * @since 1.0.0
 */

const MaxLength: u64 = 68_719_476_704;

/**
 * The reduction constant of GHASH, the polynomial `x^128 + x^7 + x^2 + x + 1` in GCM's reflected bit order.
 *
 * @remarks
 * A shift right moves the lowest bit of the 128-bit value out,
 * and when that bit was set, XORing this constant into the top byte reduces the result.
 *
 * @since 1.0.0
 */

const Reduce: u64 = 0xE100_0000_0000_0000;

/**
 * Reads a big-endian 64-bit word from eight bytes.
 *
 * @param bytes - The bytes
 * @param at - The index of the highest byte
 * @returns The word
 *
 * @remarks
 * GHASH treats a block as a big-endian 128-bit number, held as two of these words.
 *
 * @since 1.0.0
 */

function load64(bytes: readonly u8[], at: usize): u64 {
    let word: u64 = 0;
    for (const i of 0..8) word = (word << 8) | (bytes[at + i] as u64);
    return word;
}

/**
 * Writes a 64-bit word as eight big-endian bytes.
 *
 * @param out - The buffer
 * @param at - The index of the highest byte
 * @param word - The word
 *
 * @remarks
 * It writes the GHASH result and the bit lengths of the last GHASH block.
 *
 * @since 1.0.0
 */

function store64(out: u8[], at: usize, word: u64): void {
    for (const i of 0..8) out[at + i] = @truncate(u8, word >> (56 - 8 * i as u64));
}

/**
 * A running GHASH, the universal hash of GCM over GF(2^128).
 *
 * @remarks
 * It follows NIST SP 800-38D, section 6.4, and holds the hash key and the running value as two 64-bit halves.
 * Each block is XORed in and the sum is multiplied by the hash key with a bitwise multiplication.
 * The multiplication selects with masks for all 128 bits, with no table, and no branch or index on data,
 * so it runs in the same time for every key and message.
 *
 * @since 1.0.0
 */

struct Ghash {
    /**
     * The high 64 bits of the hash key, the encryption of the zero block.
     *
     * @remarks
     * It's secret, since anyone who knows it can forge tags.
     *
     * @since 1.0.0
     */

    keyHigh: u64,

    /**
     * The low 64 bits of the hash key.
     *
     * @remarks
     * It pairs with `keyHigh` to make the 128-bit hash key.
     *
     * @since 1.0.0
     */

    keyLow: u64,

    /**
     * The high 64 bits of the running value.
     *
     * @remarks
     * It starts at zero.
     *
     * @since 1.0.0
     */

    high: u64,

    /**
     * The low 64 bits of the running value.
     *
     * @remarks
     * It pairs with `high` to make the 128-bit running value.
     *
     * @since 1.0.0
     */

    low: u64,

    /**
     * Starts a GHASH under a hash key.
     *
     * @param key - The 16-byte hash key
     * @returns The hash, with a running value of zero
     *
     * @remarks
     * GCM's hash key is the AES encryption of the zero block under the cipher key.
     *
     * @since 1.0.0
     */

    init(key: u8[16]): Ghash {
        return Ghash { keyHigh: load64(&key, 0), keyLow: load64(&key, 8), high: 0, low: 0 };
    }

    /**
     * Multiplies the running value by the hash key in GF(2^128).
     *
     * @remarks
     * It's algorithm 1 of NIST SP 800-38D, run for all 128 bits.
     * Each bit of the running value, from the highest, adds the shifted key through a mask,
     * and each shift reduces through a mask built from the bit shifted out.
     * The order of the bits is fixed, so the branch on the loop index never depends on data.
     *
     * @since 1.0.0
     */

    multiply(this: *Ghash): void {
        let zHigh: u64 = 0;
        let zLow: u64 = 0;
        let vHigh = this.keyHigh;
        let vLow = this.keyLow;
        for (const i of 0..128) {
            const word = i < 64 ? this.high : this.low;
            const bit = (word >> (63 - (i % 64)) as u64) & 1;
            const take = (0 as u64) -% bit;
            zHigh ^= vHigh & take;
            zLow ^= vLow & take;
            const carry = (0 as u64) -% (vLow & 1);
            vLow = (vLow >> 1) | (vHigh << 63);
            vHigh = (vHigh >> 1) ^ (Reduce & carry);
        }
        this.high = zHigh;
        this.low = zLow;
    }

    /**
     * Hashes bytes, padding the last partial block with zeros.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * Each call pads its own tail, which is exactly how GCM hashes the associated data and then the ciphertext.
     * Splitting one input across two calls would pad in the middle and give a different hash.
     * An empty slice changes nothing.
     *
     * @since 1.0.0
     */

    update(this: *Ghash, bytes: readonly u8[]): void {
        let at: usize = 0;
        while (at < bytes.len) {
            let block: u8[16] = undefined;
            for (const _, i of block) block[i] = 0;
            const take = bytes.len - at < 16 ? bytes.len - at : 16;
            for (const i of 0..take) block[i] = bytes[at + i];
            this.high ^= load64(&block, 0);
            this.low ^= load64(&block, 8);
            this.multiply();
            at += take;
        }
    }

    /**
     * Writes the running value as 16 big-endian bytes.
     *
     * @returns The hash
     *
     * @remarks
     * It leaves the state alone.
     *
     * @since 1.0.0
     */

    finish(this: readonly *Ghash): u8[16] {
        let out: u8[16] = undefined;
        store64(&out, 0, this.high);
        store64(&out, 8, this.low);
        return out;
    }
}

/**
 * Checks the key, the nonce, and the lengths of a seal or an open.
 *
 * @param key - The key
 * @param nonce - The nonce
 * @param input - The plaintext or the ciphertext
 * @param out - The output buffer
 * @throws AeadError.BadKeyLength when the key is not 16, 24, or 32 bytes
 * @throws AeadError.BadNonceLength when the nonce is not 12 bytes
 * @throws AeadError.TooLong when the input is longer than {@link MaxLength}
 * @throws AeadError.ShortBuffer when `out` is shorter than the input
 *
 * @remarks
 * It runs before any other work, so an error never leaves partial output behind,
 * and the key length is reported as an AEAD error rather than an AES error.
 *
 * @since 1.0.0
 */

function check(key: readonly u8[], nonce: readonly u8[], input: readonly u8[], out: u8[]): void | Error {
    if (key.len != 16 && key.len != 24 && key.len != 32) throw AeadError.BadKeyLength;
    if (nonce.len != 12) throw AeadError.BadNonceLength;
    if (input.len as u64 > MaxLength) throw AeadError.TooLong;
    if (out.len < input.len) throw AeadError.ShortBuffer;
}

/**
 * Builds the counter block of a nonce and a block counter.
 *
 * @param nonce - The 12-byte nonce
 * @param counter - The 32-bit block counter
 * @returns The nonce followed by the counter, big-endian
 *
 * @remarks
 * With a 12-byte nonce, counter 1 masks the tag and the message uses counters 2 and up.
 *
 * @since 1.0.0
 */

function counterBlock(nonce: readonly u8[], counter: u32): u8[16] {
    let block: u8[16] = undefined;
    for (const i of 0..12) block[i] = nonce[i];
    block[12] = @truncate(u8, counter >> 24);
    block[13] = @truncate(u8, counter >> 16);
    block[14] = @truncate(u8, counter >> 8);
    block[15] = @truncate(u8, counter);
    return block;
}

/**
 * Encrypts or decrypts bytes in GCM's counter mode, from counter 2 on.
 *
 * @param aes - The cipher
 * @param nonce - The 12-byte nonce
 * @param input - The plaintext or the ciphertext
 * @param out - The buffer for the result, at least as long as `input`
 *
 * @remarks
 * It's GCTR of NIST SP 800-38D, section 6.5, starting from the incremented initial counter block.
 * The caller has checked the length, so the counter never wraps.
 * `out` may be the same buffer as `input`, since each byte is read before it is written.
 *
 * @since 1.0.0
 */

function ctr(aes: readonly *Aes, nonce: readonly u8[], input: readonly u8[], out: u8[]): void {
    let counter: u32 = 2;
    let at: usize = 0;
    while (at < input.len) {
        const stream = aes.encryptBlock(counterBlock(nonce, counter));
        const take = input.len - at < 16 ? input.len - at : 16;
        for (const i of 0..take) out[at + i] = input[at + i] ^ stream[i];
        at += take;
        counter +%= 1;
    }
}

/**
 * Computes the tag of a GCM message.
 *
 * @param aes - The cipher
 * @param nonce - The 12-byte nonce
 * @param aad - The associated data
 * @param ciphertext - The ciphertext
 * @returns The 16-byte tag
 *
 * @remarks
 * It hashes the associated data, the ciphertext, and a block of both lengths in bits,
 * each padded to 16 bytes, under the hash key.
 * The hash XORed with the encryption of counter block 1 is the tag.
 *
 * @since 1.0.0
 */

function tagOf(aes: readonly *Aes, nonce: readonly u8[], aad: readonly u8[], ciphertext: readonly u8[]): u8[16] {
    let zero: u8[16] = undefined;
    for (const _, i of zero) zero[i] = 0;
    let ghash = Ghash.init(aes.encryptBlock(zero));
    ghash.update(aad);
    ghash.update(ciphertext);
    let lengths: u8[16] = undefined;
    store64(&lengths, 0, (aad.len as u64) << 3);
    store64(&lengths, 8, (ciphertext.len as u64) << 3);
    ghash.update(&lengths);

    const mask = aes.encryptBlock(counterBlock(nonce, 1));
    let tag = ghash.finish();
    for (const i of 0..16) tag[i] ^= mask[i];
    return tag;
}

/**
 * Encrypts and authenticates a message with AES-GCM.
 *
 * @param key - The 16, 24, or 32-byte secret key, for AES-128, AES-192, or AES-256
 * @param nonce - The 12-byte nonce, which must never repeat under the same key
 * @param aad - The associated data, which the tag covers but which stays unencrypted
 * @param plaintext - The message
 * @param out - The buffer for the ciphertext, at least as long as `plaintext`
 * @returns The 16-byte tag, which the receiver needs along with the ciphertext
 * @throws AeadError.BadKeyLength when the key is not 16, 24, or 32 bytes
 * @throws AeadError.BadNonceLength when the nonce is not 12 bytes
 * @throws AeadError.TooLong when the plaintext is longer than 68,719,476,704 bytes
 * @throws AeadError.ShortBuffer when `out` is shorter than `plaintext`
 *
 * @remarks
 * It's GCM of NIST SP 800-38D with a 96-bit nonce and a full 128-bit tag.
 * The ciphertext fills the start of `out`, as many bytes as the plaintext has, and the tag comes back separately.
 * Never reuse a nonce with the same key.
 * A repeated nonce reveals the XOR of the two plaintexts and lets anyone recover the hash key and forge tags.
 * With random nonces, stop at about 4 billion messages per key.
 * AES and GHASH here are constant-time and use no tables, so they are much slower than hardware AES.
 * Prefer {@link chacha20Poly1305Seal} unless something requires AES.
 * `out` may be the same buffer as `plaintext`.
 *
 * @example
 * ```hx
 * let ciphertext: u8[3] = undefined;
 * const tag = try aesGcmSeal(&key, &nonce, "header", "abc", &ciphertext);
 * let plain: u8[3] = undefined;
 * try aesGcmOpen(&key, &nonce, "header", &ciphertext, &tag, &plain); // "abc"
 * ```
 *
 * @since 1.0.0
 */

export function aesGcmSeal(
    key: readonly u8[], nonce: readonly u8[], aad: readonly u8[], plaintext: readonly u8[], out: u8[],
): u8[16] | Error {
    try check(key, nonce, plaintext, out);
    const aes = try Aes.init(key);
    ctr(&aes, nonce, plaintext, out);

    return tagOf(&aes, nonce, aad, out[0..plaintext.len]);
}

/**
 * Checks and decrypts a message sealed with AES-GCM.
 *
 * @param key - The 16, 24, or 32-byte secret key
 * @param nonce - The 12-byte nonce that the message was sealed with
 * @param aad - The associated data that the message was sealed with
 * @param ciphertext - The ciphertext
 * @param tag - The 16-byte tag from {@link aesGcmSeal}
 * @param out - The buffer for the plaintext, at least as long as `ciphertext`
 * @returns The part of `out` that holds the plaintext
 * @throws AeadError.BadKeyLength when the key is not 16, 24, or 32 bytes
 * @throws AeadError.BadNonceLength when the nonce is not 12 bytes
 * @throws AeadError.TooLong when the ciphertext is longer than 68,719,476,704 bytes
 * @throws AeadError.ShortBuffer when `out` is shorter than `ciphertext`
 * @throws AeadError.BadTag when the tag doesn't match
 *
 * @remarks
 * It computes the tag of the ciphertext and compares it with {@link timingSafeEqual} before decrypting,
 * so a forged or damaged message never releases any plaintext, and `out` stays as it was.
 * Only full 16-byte tags are accepted, since truncated GCM tags weaken the authentication.
 * `out` may be the same buffer as `ciphertext`.
 *
 * @example
 * ```hx
 * let plain: u8[3] = undefined;
 * try aesGcmOpen(&key, &nonce, "header", &ciphertext, &tag, &plain); // "abc"
 * tag[0] ^= 1;
 * aesGcmOpen(&key, &nonce, "header", &ciphertext, &tag, &plain); // throws AeadError.BadTag
 * ```
 *
 * @since 1.0.0
 */

export function aesGcmOpen(
    key: readonly u8[], nonce: readonly u8[], aad: readonly u8[], ciphertext: readonly u8[], tag: readonly u8[],
    out: u8[],
): u8[] | Error {
    try check(key, nonce, ciphertext, out);
    const aes = try Aes.init(key);
    const expected = tagOf(&aes, nonce, aad, ciphertext);
    if (!timingSafeEqual(&expected, tag)) throw AeadError.BadTag;
    ctr(&aes, nonce, ciphertext, out);

    return out[0..ciphertext.len];
}
