/**
 * Exports
 */

export { ChaCha20Error } from "@chacha20/errors/chacha20.error";

/**
 * Imports
 */

import { ChaCha20Error } from "@chacha20/errors/chacha20.error";

/**
 * The four words that open every ChaCha20 state, the text `expand 32-byte k` in little-endian.
 *
 * @remarks
 * RFC 8439 fixes them in section 2.3, and they fill words 0 to 3 of the state before the key.
 *
 * @since 1.0.0
 */

const Sigma: u32[4] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574];

/**
 * The size of one block of key stream in bytes.
 *
 * @remarks
 * Each block uses one value of the counter, so a message of `n` bytes takes `n / 64` blocks, rounded up.
 *
 * @since 1.0.0
 */

const BlockSize: usize = 64;

/**
 * Rotates a word to the left.
 *
 * @param x - The word to rotate
 * @param n - The number of bits to rotate by, from 1 to 31
 * @returns The word with its top `n` bits moved to the bottom
 *
 * @remarks
 * A count of 0 would shift `x` right by 32, which the language rejects,
 * so only call it with the counts of the quarter round: 16, 12, 8, and 7.
 * It takes the same time for every input.
 *
 * @since 1.0.0
 */

function rotl(x: u32, n: u32): u32 {
    return (x << n) | (x >> (32 - n));
}

/**
 * Reads a little-endian word from four bytes.
 *
 * @param bytes - The bytes
 * @param at - The index of the lowest byte
 * @returns The word
 *
 * @remarks
 * The caller has checked the length, so the four bytes from `at` on always exist.
 *
 * @since 1.0.0
 */

function load32(bytes: readonly u8[], at: usize): u32 {
    return (bytes[at] as u32) | ((bytes[at + 1] as u32) << 8) | ((bytes[at + 2] as u32) << 16) |
        ((bytes[at + 3] as u32) << 24);
}

/**
 * Runs the ChaCha quarter round on four words of a state.
 *
 * @param x - The 16 words of the working state
 * @param a - The index of the first word
 * @param b - The index of the second word
 * @param c - The index of the third word
 * @param d - The index of the fourth word
 *
 * @remarks
 * It follows section 2.1 of RFC 8439: four rounds of add, XOR, and rotate,
 * with every addition wrapping modulo 2 to the power of 32.
 * The indexes are fixed by the round, never by data, so the memory access pattern reveals nothing.
 *
 * @since 1.0.0
 */

function quarterRound(x: u32[], a: usize, b: usize, c: usize, d: usize): void {
    x[a] +%= x[b];
    x[d] = rotl(x[d] ^ x[a], 16);
    x[c] +%= x[d];
    x[b] = rotl(x[b] ^ x[c], 12);
    x[a] +%= x[b];
    x[d] = rotl(x[d] ^ x[a], 8);
    x[c] +%= x[d];
    x[b] = rotl(x[b] ^ x[c], 7);
}

/**
 * Computes one block of key stream without checking the lengths.
 *
 * @param key - The 32-byte key
 * @param nonce - The 12-byte nonce
 * @param counter - The block counter
 * @returns The 64 bytes of key stream
 *
 * @remarks
 * It builds the state of section 2.3 of RFC 8439, runs 10 double rounds of a column round and a diagonal round,
 * adds the starting state back in, and writes the 16 words out little-endian.
 * {@link chacha20Block} and {@link chacha20} check the lengths first and then call it.
 *
 * @since 1.0.0
 */

function block(key: readonly u8[], nonce: readonly u8[], counter: u32): u8[64] {
    let state: u32[16] = undefined;
    for (const i of 0..4) state[i] = Sigma[i];
    for (const i of 0..8) state[4 + i] = load32(key, 4 * i);
    state[12] = counter;
    for (const i of 0..3) state[13 + i] = load32(nonce, 4 * i);

    let x: u32[16] = state;
    for (const _ of 0..10) {
        quarterRound(&x, 0, 4, 8, 12);
        quarterRound(&x, 1, 5, 9, 13);
        quarterRound(&x, 2, 6, 10, 14);
        quarterRound(&x, 3, 7, 11, 15);
        quarterRound(&x, 0, 5, 10, 15);
        quarterRound(&x, 1, 6, 11, 12);
        quarterRound(&x, 2, 7, 8, 13);
        quarterRound(&x, 3, 4, 9, 14);
    }

    let out: u8[64] = undefined;
    for (const i of 0..16) {
        const word = x[i] +% state[i];
        out[4 * i] = @truncate(u8, word);
        out[4 * i + 1] = @truncate(u8, word >> 8);
        out[4 * i + 2] = @truncate(u8, word >> 16);
        out[4 * i + 3] = @truncate(u8, word >> 24);
    }
    return out;
}

/**
 * Checks the key and the nonce of a ChaCha20 call.
 *
 * @param key - The key
 * @param nonce - The nonce
 * @throws ChaCha20Error.BadKeyLength when the key is not 32 bytes
 * @throws ChaCha20Error.BadNonceLength when the nonce is not 12 bytes
 *
 * @remarks
 * Both public functions run it before any other work,
 * so a wrong length never reaches {@link block}, which reads fixed offsets.
 *
 * @since 1.0.0
 */

function checkKeyAndNonce(key: readonly u8[], nonce: readonly u8[]): void | Error {
    if (key.len != 32) throw ChaCha20Error.BadKeyLength;
    if (nonce.len != 12) throw ChaCha20Error.BadNonceLength;
}

/**
 * Computes one 64-byte block of ChaCha20 key stream.
 *
 * @param key - The 32-byte key
 * @param nonce - The 12-byte nonce
 * @param counter - The block counter
 * @returns The 64 bytes of key stream for this counter
 * @throws ChaCha20Error.BadKeyLength when the key is not 32 bytes
 * @throws ChaCha20Error.BadNonceLength when the nonce is not 12 bytes
 *
 * @remarks
 * It's the block function of section 2.3 of RFC 8439.
 * ChaCha20-Poly1305 takes the first 32 bytes of block 0 as its one-time Poly1305 key,
 * and {@link chacha20} XORs blocks from the given counter on into the message.
 * Use {@link chacha20} to encrypt, since this function only gives the raw key stream.
 *
 * @example
 * ```hx
 * // the key 00 01 02 ... 1f and the nonce 00 00 00 09 00 00 00 4a 00 00 00 00 of RFC 8439, section 2.3.2
 * const stream = try chacha20Block(&key, &nonce, 1);
 * stream[0]; // 0x10
 * stream[1]; // 0xF1
 * ```
 *
 * @since 1.0.0
 */

export function chacha20Block(key: readonly u8[], nonce: readonly u8[], counter: u32): u8[64] | Error {
    try checkKeyAndNonce(key, nonce);

    return block(key, nonce, counter);
}

/**
 * Encrypts or decrypts bytes with the ChaCha20 stream cipher.
 *
 * @param key - The 32-byte secret key
 * @param nonce - The 12-byte nonce, which must never repeat under the same key
 * @param counter - The counter of the first block, usually 0 or 1
 * @param input - The plaintext to encrypt or the ciphertext to decrypt
 * @param out - The buffer for the result, at least as long as `input`
 * @returns The part of `out` that holds the result
 * @throws ChaCha20Error.BadKeyLength when the key is not 32 bytes
 * @throws ChaCha20Error.BadNonceLength when the nonce is not 12 bytes
 * @throws ChaCha20Error.ShortBuffer when `out` is shorter than `input`
 * @throws ChaCha20Error.CounterOverflow when the input needs a counter past `0xFFFFFFFF`
 *
 * @remarks
 * It follows section 2.4 of RFC 8439: block `i` of the input is XORed with the key stream of `counter + i`,
 * so the same call both encrypts and decrypts.
 * Never reuse a nonce with the same key.
 * Two messages under one key and nonce share a key stream,
 * and the XOR of their ciphertexts is the XOR of their plaintexts.
 * The cipher alone doesn't detect changes to the ciphertext,
 * so use {@link chacha20Poly1305Seal} unless something else authenticates the bytes.
 * `out` may be the same buffer as `input`, since each byte is read before it is written.
 * The time depends only on the length of the input.
 *
 * @example
 * ```hx
 * let out: u8[3] = undefined;
 * const sealed = try chacha20(&key, &nonce, 1, "abc", &out);
 * let back: u8[3] = undefined;
 * try chacha20(&key, &nonce, 1, sealed, &back); // "abc"
 * ```
 *
 * @since 1.0.0
 */

export function chacha20(
    key: readonly u8[], nonce: readonly u8[], counter: u32, input: readonly u8[], out: u8[],
): u8[] | Error {
    try checkKeyAndNonce(key, nonce);
    if (out.len < input.len) throw ChaCha20Error.ShortBuffer;
    const blocks = ((input.len as u64) + 63) / 64;
    if ((counter as u64) + blocks > 0x1_0000_0000) throw ChaCha20Error.CounterOverflow;

    let next = counter;
    let at: usize = 0;
    while (at < input.len) {
        const stream = block(key, nonce, next);
        const take = input.len - at < BlockSize ? input.len - at : BlockSize;
        for (const i of 0..take) out[at + i] = input[at + i] ^ stream[i];
        at += take;
        next +%= 1;
    }
    return out[0..input.len];
}
