/**
 * Imports
 */

import { Blake2Error } from "@blake2/errors/blake2.error";
import { Blake2Sigma, Blake2bInitialState, Blake2sInitialState } from "@blake2/constants/blake2.constant";

/**
 * Rotates a 64-bit word to the right.
 *
 * @param x - The word
 * @param n - The number of bits, from 1 to 63
 * @returns The word with its low `n` bits moved to the top
 *
 * @remarks
 * A count of 0 would shift `x` left by 64, so only the counts of BLAKE2b's mixing step may reach it.
 *
 * @since 1.0.0
 */

function rotr64(x: u64, n: u64): u64 {
    return (x >> n) | (x << (64 - n));
}

/**
 * Rotates a 32-bit word to the right.
 *
 * @param x - The word
 * @param n - The number of bits, from 1 to 31
 * @returns The word with its low `n` bits moved to the top
 *
 * @remarks
 * A count of 0 would shift `x` left by 32, so only the counts of BLAKE2s's mixing step may reach it.
 *
 * @since 1.0.0
 */

function rotr32(x: u32, n: u32): u32 {
    return (x >> n) | (x << (32 - n));
}

/**
 * Mixes two message words into four words of BLAKE2b's working vector.
 *
 * @param v - The working vector
 * @param a - The index of the first word
 * @param b - The index of the second word
 * @param c - The index of the third word
 * @param d - The index of the fourth word
 * @param x - The first message word
 * @param y - The second message word
 *
 * @remarks
 * It's the function G of RFC 7693 with BLAKE2b's rotations of 32, 24, 16, and 63 bits.
 * The indexes are fixed by the round, so nothing that it reads depends on the key or the message.
 *
 * @since 1.0.0
 */

function mixBlake2b(v: *u64[16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64): void {
    v[a] = v[a] +% v[b] +% x;
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = v[c] +% v[d];
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = v[a] +% v[b] +% y;
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = v[c] +% v[d];
    v[b] = rotr64(v[b] ^ v[c], 63);
}

/**
 * Mixes two message words into four words of BLAKE2s's working vector.
 *
 * @param v - The working vector
 * @param a - The index of the first word
 * @param b - The index of the second word
 * @param c - The index of the third word
 * @param d - The index of the fourth word
 * @param x - The first message word
 * @param y - The second message word
 *
 * @remarks
 * It's the function G of RFC 7693 with BLAKE2s's rotations of 16, 12, 8, and 7 bits.
 * The indexes are fixed by the round, so nothing that it reads depends on the key or the message.
 *
 * @since 1.0.0
 */

function mixBlake2s(v: *u32[16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32): void {
    v[a] = v[a] +% v[b] +% x;
    v[d] = rotr32(v[d] ^ v[a], 16);
    v[c] = v[c] +% v[d];
    v[b] = rotr32(v[b] ^ v[c], 12);
    v[a] = v[a] +% v[b] +% y;
    v[d] = rotr32(v[d] ^ v[a], 8);
    v[c] = v[c] +% v[d];
    v[b] = rotr32(v[b] ^ v[c], 7);
}

/**
 * Runs the 12 rounds of BLAKE2b on one block and folds the result into the state.
 *
 * @param state - The eight words of the running hash
 * @param block - The 128 bytes of the block
 * @param count - The low 64 bits of the number of bytes hashed, this block included
 * @param countHigh - The high 64 bits of that number
 * @param last - Whether this is the final block
 *
 * @remarks
 * It reads the block as 16 little-endian words and follows the function F of RFC 7693.
 * The last block inverts word 14 of the working vector, which keeps a final block apart from an inner one.
 *
 * @since 1.0.0
 */

function compressBlake2b(state: *u64[8], block: readonly u8[], count: u64, countHigh: u64, last: bool): void {
    let m: u64[16] = undefined;
    for (const i of 0..16) {
        let word: u64 = 0;
        for (const j of 0..8) word = word | ((block[i * 8 + j] as u64) << ((j * 8) as u64));
        m[i] = word;
    }

    let v: u64[16] = undefined;
    for (const i of 0..8) {
        v[i] = state[i];
        v[i + 8] = Blake2bInitialState[i];
    }
    v[12] = v[12] ^ count;
    v[13] = v[13] ^ countHigh;
    if (last) v[14] = ~v[14];

    for (const r of 0..12) {
        const s = (r % 10) * 16;
        mixBlake2b(&v, 0, 4, 8, 12, m[Blake2Sigma[s]], m[Blake2Sigma[s + 1]]);
        mixBlake2b(&v, 1, 5, 9, 13, m[Blake2Sigma[s + 2]], m[Blake2Sigma[s + 3]]);
        mixBlake2b(&v, 2, 6, 10, 14, m[Blake2Sigma[s + 4]], m[Blake2Sigma[s + 5]]);
        mixBlake2b(&v, 3, 7, 11, 15, m[Blake2Sigma[s + 6]], m[Blake2Sigma[s + 7]]);
        mixBlake2b(&v, 0, 5, 10, 15, m[Blake2Sigma[s + 8]], m[Blake2Sigma[s + 9]]);
        mixBlake2b(&v, 1, 6, 11, 12, m[Blake2Sigma[s + 10]], m[Blake2Sigma[s + 11]]);
        mixBlake2b(&v, 2, 7, 8, 13, m[Blake2Sigma[s + 12]], m[Blake2Sigma[s + 13]]);
        mixBlake2b(&v, 3, 4, 9, 14, m[Blake2Sigma[s + 14]], m[Blake2Sigma[s + 15]]);
    }

    for (const i of 0..8) state[i] = state[i] ^ v[i] ^ v[i + 8];
}

/**
 * Runs the 10 rounds of BLAKE2s on one block and folds the result into the state.
 *
 * @param state - The eight words of the running hash
 * @param block - The 64 bytes of the block
 * @param count - The low 32 bits of the number of bytes hashed, this block included
 * @param countHigh - The high 32 bits of that number
 * @param last - Whether this is the final block
 *
 * @remarks
 * It reads the block as 16 little-endian words and follows the function F of RFC 7693.
 * The last block inverts word 14 of the working vector, which keeps a final block apart from an inner one.
 *
 * @since 1.0.0
 */

function compressBlake2s(state: *u32[8], block: readonly u8[], count: u32, countHigh: u32, last: bool): void {
    let m: u32[16] = undefined;
    for (const i of 0..16) {
        m[i] = (block[i * 4] as u32) | ((block[i * 4 + 1] as u32) << 8) |
               ((block[i * 4 + 2] as u32) << 16) | ((block[i * 4 + 3] as u32) << 24);
    }

    let v: u32[16] = undefined;
    for (const i of 0..8) {
        v[i] = state[i];
        v[i + 8] = Blake2sInitialState[i];
    }
    v[12] = v[12] ^ count;
    v[13] = v[13] ^ countHigh;
    if (last) v[14] = ~v[14];

    for (const r of 0..10) {
        const s = r * 16;
        mixBlake2s(&v, 0, 4, 8, 12, m[Blake2Sigma[s]], m[Blake2Sigma[s + 1]]);
        mixBlake2s(&v, 1, 5, 9, 13, m[Blake2Sigma[s + 2]], m[Blake2Sigma[s + 3]]);
        mixBlake2s(&v, 2, 6, 10, 14, m[Blake2Sigma[s + 4]], m[Blake2Sigma[s + 5]]);
        mixBlake2s(&v, 3, 7, 11, 15, m[Blake2Sigma[s + 6]], m[Blake2Sigma[s + 7]]);
        mixBlake2s(&v, 0, 5, 10, 15, m[Blake2Sigma[s + 8]], m[Blake2Sigma[s + 9]]);
        mixBlake2s(&v, 1, 6, 11, 12, m[Blake2Sigma[s + 10]], m[Blake2Sigma[s + 11]]);
        mixBlake2s(&v, 2, 7, 8, 13, m[Blake2Sigma[s + 12]], m[Blake2Sigma[s + 13]]);
        mixBlake2s(&v, 3, 4, 9, 14, m[Blake2Sigma[s + 14]], m[Blake2Sigma[s + 15]]);
    }

    for (const i of 0..8) state[i] = state[i] ^ v[i] ^ v[i + 8];
}

/**
 * Starts a BLAKE2b without checking its parameters.
 *
 * @param outLen - The output length, from 1 to 64
 * @param key - The key, of up to 64 bytes
 * @returns The hash
 *
 * @remarks
 * It folds the parameter block of RFC 7693 into word 0 of the state.
 * A key fills a whole block of its own, padded with zeros, which stays buffered until more bytes or the end arrive.
 * {@link Blake2b.init} checks the lengths first, and {@link blake2b} calls it with lengths that are always valid.
 *
 * @since 1.0.0
 */

function startBlake2b(outLen: usize, key: readonly u8[]): Blake2b {
    let state = Blake2bInitialState;
    state[0] = state[0] ^ 0x0101_0000 ^ ((key.len as u64) << 8) ^ (outLen as u64);
    let hash = Blake2b { state, count: 0, countHigh: 0, block: undefined, used: 0, outLen };
    if (key.len > 0) {
        for (const i of 0..128) hash.block[i] = 0;
        for (const byte, i of key) hash.block[i] = byte;
        hash.used = 128;
    }

    return hash;
}

/**
 * Starts a BLAKE2s without checking its parameters.
 *
 * @param outLen - The output length, from 1 to 32
 * @param key - The key, of up to 32 bytes
 * @returns The hash
 *
 * @remarks
 * It folds the parameter block of RFC 7693 into word 0 of the state.
 * A key fills a whole block of its own, padded with zeros, which stays buffered until more bytes or the end arrive.
 * {@link Blake2s.init} checks the lengths first, and {@link blake2s} calls it with lengths that are always valid.
 *
 * @since 1.0.0
 */

function startBlake2s(outLen: usize, key: readonly u8[]): Blake2s {
    let state = Blake2sInitialState;
    state[0] = state[0] ^ 0x0101_0000 ^ ((key.len as u32) << 8) ^ (outLen as u32);
    let hash = Blake2s { state, count: 0, countHigh: 0, block: undefined, used: 0, outLen };
    if (key.len > 0) {
        for (const i of 0..64) hash.block[i] = 0;
        for (const byte, i of key) hash.block[i] = byte;
        hash.used = 64;
    }

    return hash;
}

/**
 * Compresses the last block of a copy of a BLAKE2b and returns all 64 bytes of its state.
 *
 * @param hash - The hash to finish
 * @returns The full state, little-endian, whose first `outLen` bytes are the digest
 *
 * @remarks
 * It pads the waiting bytes with zeros, counts only the real ones, and compresses with the last-block flag.
 * Working on a copy is what lets {@link Blake2b.finish} leave the hash usable.
 *
 * @since 1.0.0
 */

function outputBlake2b(hash: readonly *Blake2b): u8[64] {
    let copy = *hash;
    const n = copy.used as u64;
    copy.count +%= n;
    if (copy.count < n) copy.countHigh +%= 1;
    for (const i of 0..128 - copy.used) copy.block[copy.used + i] = 0;
    compressBlake2b(&copy.state, &copy.block, copy.count, copy.countHigh, true);

    let out: u8[64] = undefined;
    for (const word, i of copy.state) {
        for (const j of 0..8) out[i * 8 + j] = @truncate(u8, word >> ((j * 8) as u64));
    }

    return out;
}

/**
 * Compresses the last block of a copy of a BLAKE2s and returns all 32 bytes of its state.
 *
 * @param hash - The hash to finish
 * @returns The full state, little-endian, whose first `outLen` bytes are the digest
 *
 * @remarks
 * It pads the waiting bytes with zeros, counts only the real ones, and compresses with the last-block flag.
 * Working on a copy is what lets {@link Blake2s.finish} leave the hash usable.
 *
 * @since 1.0.0
 */

function outputBlake2s(hash: readonly *Blake2s): u8[32] {
    let copy = *hash;
    const n = copy.used as u32;
    copy.count +%= n;
    if (copy.count < n) copy.countHigh +%= 1;
    for (const i of 0..64 - copy.used) copy.block[copy.used + i] = 0;
    compressBlake2s(&copy.state, &copy.block, copy.count, copy.countHigh, true);

    let out: u8[32] = undefined;
    for (const word, i of copy.state) {
        out[i * 4] = @truncate(u8, word);
        out[i * 4 + 1] = @truncate(u8, word >> 8);
        out[i * 4 + 2] = @truncate(u8, word >> 16);
        out[i * 4 + 3] = @truncate(u8, word >> 24);
    }

    return out;
}

/**
 * A running BLAKE2b that takes its bytes in pieces, with an output of 1 to 64 bytes and an optional key.
 *
 * @remarks
 * It follows RFC 7693 and works on 64-bit words, so it's the faster variant on 64-bit targets.
 * Reach for it over {@link blake2b} when the bytes arrive in chunks, when the output must be shorter,
 * or when a key turns it into a MAC.
 * The output length is part of the parameters, so a 32-byte BLAKE2b is not the first half of a 64-byte one.
 * Check a keyed tag with `timingSafeEqual` from `@compare`, never with an ordinary comparison.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 *
 * @example
 * ```hx
 * let hash = try Blake2b.init(32, "");
 * hash.update("a");
 * hash.update("bc");
 * let out: u8[32] = undefined;
 * try hash.finish(&out); // bddd813c...68d52319 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Blake2b {
    /**
     * The eight words of the running hash.
     *
     * @remarks
     * They start from the SHA-512 initial state with the parameter block folded into word 0.
     *
     * @example
     * ```hx
     * (try Blake2b.init(64, "")).state[0]; // 0x6A09E667F2BDC948
     * ```
     *
     * @since 1.0.0
     */

    state: u64[8],

    /**
     * The low 64 bits of the number of bytes compressed so far.
     *
     * @remarks
     * Each compression adds the bytes of its block, and the key block counts as 128 bytes.
     * It wraps into `countHigh`.
     *
     * @example
     * ```hx
     * let hash = try Blake2b.init(64, "");
     * hash.update(bytes[0..129]);
     * hash.count; // 128
     * ```
     *
     * @since 1.0.0
     */

    count: u64,

    /**
     * The high 64 bits of the number of bytes compressed so far.
     *
     * @remarks
     * It only changes once `count` wraps, which takes more input than any program will hash.
     *
     * @example
     * ```hx
     * (try Blake2b.init(64, "")).countHigh; // 0
     * ```
     *
     * @since 1.0.0
     */

    countHigh: u64,

    /**
     * The block of 128 bytes that waits for the next compression.
     *
     * @remarks
     * Only its first `used` bytes hold input.
     * A full block stays here until more bytes arrive,
     * since BLAKE2 must know which block is the last one before compressing it.
     *
     * @example
     * ```hx
     * let hash = try Blake2b.init(64, "");
     * hash.update("abc");
     * hash.block[0]; // 0x61
     * ```
     *
     * @since 1.0.0
     */

    block: u8[128],

    /**
     * The number of bytes waiting in `block`.
     *
     * @remarks
     * It runs from 0 to 128, and a key alone fills the block.
     *
     * @example
     * ```hx
     * let hash = try Blake2b.init(64, "");
     * hash.update("abc");
     * hash.used; // 3
     * ```
     *
     * @since 1.0.0
     */

    used: usize,

    /**
     * The number of bytes that {@link Blake2b.finish} writes.
     *
     * @remarks
     * It's fixed at the start, since the parameter block mixes it into the state.
     *
     * @example
     * ```hx
     * (try Blake2b.init(20, "")).outLen; // 20
     * ```
     *
     * @since 1.0.0
     */

    outLen: usize,

    /**
     * Starts a BLAKE2b with an output length and an optional key.
     *
     * @param outLen - The output length, from 1 to 64 bytes
     * @param key - The key, of up to 64 bytes, or an empty slice for a plain hash
     * @returns The hash
     * @throws Blake2Error.BadOutputLength when `outLen` is 0 or above 64
     * @throws Blake2Error.BadKeyLength when `key` is longer than 64 bytes
     *
     * @remarks
     * A keyed BLAKE2b is a MAC on its own and needs no HMAC around it.
     * A key of 32 random bytes or more gives its full strength.
     *
     * @example
     * ```hx
     * let hash = try Blake2b.init(64, "");
     * let out: u8[64] = undefined;
     * try hash.finish(&out); // 786a02f7...fe9be2ce as hex
     * Blake2b.init(0, "");   // throws Blake2Error.BadOutputLength
     * ```
     *
     * @since 1.0.0
     */

    init(outLen: usize, key: readonly u8[]): Blake2b | Error {
        if (outLen < 1 || outLen > 64) throw Blake2Error.BadOutputLength;
        if (key.len > 64) throw Blake2Error.BadKeyLength;

        return startBlake2b(outLen, key);
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * It compresses a full block only when more bytes arrive after it,
     * so the last block always waits for {@link Blake2b.finish}.
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = try Blake2b.init(64, "");
     * hash.update("abc");
     * let out: u8[64] = undefined;
     * try hash.finish(&out); // ba80a53f...d4009923 as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Blake2b, bytes: readonly u8[]): void {
        let at: usize = 0;
        while (at < bytes.len) {
            if (this.used == 128) {
                this.count +%= 128;
                if (this.count < 128) this.countHigh +%= 1;
                compressBlake2b(&this.state, &this.block, this.count, this.countHigh, false);
                this.used = 0;
            }
            const take = 128 - this.used < bytes.len - at ? 128 - this.used : bytes.len - at;
            for (const i of 0..take) this.block[this.used + i] = bytes[at + i];
            this.used += take;
            at += take;
        }
    }

    /**
     * Writes the digest of every byte added so far.
     *
     * @param out - The buffer for the digest, at least `outLen` bytes long
     * @returns The first `outLen` bytes of `out`, which hold the digest
     * @throws Blake2Error.ShortBuffer when `out` is shorter than `outLen`
     *
     * @remarks
     * It compresses the last block of a copy and leaves the state alone,
     * so more bytes may follow and a later call covers them too.
     * It writes nothing past the first `outLen` bytes of `out`.
     *
     * @example
     * ```hx
     * let hash = try Blake2b.init(20, "");
     * hash.update("abc");
     * let out: u8[20] = undefined;
     * try hash.finish(&out); // 384264f6...68b6846b as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Blake2b, out: u8[]): u8[] | Error {
        if (out.len < this.outLen) throw Blake2Error.ShortBuffer;
        const full = outputBlake2b(this);
        for (const i of 0..this.outLen) out[i] = full[i];

        return out[0..this.outLen];
    }
}

/**
 * A running BLAKE2s that takes its bytes in pieces, with an output of 1 to 32 bytes and an optional key.
 *
 * @remarks
 * It follows RFC 7693 and works on 32-bit words, so it suits 32-bit targets and microcontrollers.
 * Reach for it over {@link blake2s} when the bytes arrive in chunks, when the output must be shorter,
 * or when a key turns it into a MAC.
 * The output length is part of the parameters, so a 16-byte BLAKE2s is not the first half of a 32-byte one.
 * Check a keyed tag with `timingSafeEqual` from `@compare`, never with an ordinary comparison.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 *
 * @example
 * ```hx
 * let hash = try Blake2s.init(16, "");
 * hash.update("a");
 * hash.update("bc");
 * let out: u8[16] = undefined;
 * try hash.finish(&out); // aa493811...d200d0ae as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Blake2s {
    /**
     * The eight words of the running hash.
     *
     * @remarks
     * They start from the SHA-256 initial state with the parameter block folded into word 0.
     *
     * @example
     * ```hx
     * (try Blake2s.init(32, "")).state[0]; // 0x6B08E647
     * ```
     *
     * @since 1.0.0
     */

    state: u32[8],

    /**
     * The low 32 bits of the number of bytes compressed so far.
     *
     * @remarks
     * Each compression adds the bytes of its block, and the key block counts as 64 bytes.
     * It wraps into `countHigh`.
     *
     * @example
     * ```hx
     * let hash = try Blake2s.init(32, "");
     * hash.update(bytes[0..65]);
     * hash.count; // 64
     * ```
     *
     * @since 1.0.0
     */

    count: u32,

    /**
     * The high 32 bits of the number of bytes compressed so far.
     *
     * @remarks
     * It changes once `count` wraps, after 4 GiB of input.
     *
     * @example
     * ```hx
     * (try Blake2s.init(32, "")).countHigh; // 0
     * ```
     *
     * @since 1.0.0
     */

    countHigh: u32,

    /**
     * The block of 64 bytes that waits for the next compression.
     *
     * @remarks
     * Only its first `used` bytes hold input.
     * A full block stays here until more bytes arrive,
     * since BLAKE2 must know which block is the last one before compressing it.
     *
     * @example
     * ```hx
     * let hash = try Blake2s.init(32, "");
     * hash.update("abc");
     * hash.block[0]; // 0x61
     * ```
     *
     * @since 1.0.0
     */

    block: u8[64],

    /**
     * The number of bytes waiting in `block`.
     *
     * @remarks
     * It runs from 0 to 64, and a key alone fills the block.
     *
     * @example
     * ```hx
     * let hash = try Blake2s.init(32, "");
     * hash.update("abc");
     * hash.used; // 3
     * ```
     *
     * @since 1.0.0
     */

    used: usize,

    /**
     * The number of bytes that {@link Blake2s.finish} writes.
     *
     * @remarks
     * It's fixed at the start, since the parameter block mixes it into the state.
     *
     * @example
     * ```hx
     * (try Blake2s.init(16, "")).outLen; // 16
     * ```
     *
     * @since 1.0.0
     */

    outLen: usize,

    /**
     * Starts a BLAKE2s with an output length and an optional key.
     *
     * @param outLen - The output length, from 1 to 32 bytes
     * @param key - The key, of up to 32 bytes, or an empty slice for a plain hash
     * @returns The hash
     * @throws Blake2Error.BadOutputLength when `outLen` is 0 or above 32
     * @throws Blake2Error.BadKeyLength when `key` is longer than 32 bytes
     *
     * @remarks
     * A keyed BLAKE2s is a MAC on its own and needs no HMAC around it.
     * A key of 32 random bytes gives its full strength.
     *
     * @example
     * ```hx
     * let hash = try Blake2s.init(32, "");
     * let out: u8[32] = undefined;
     * try hash.finish(&out); // 69217a30...1ed0eef9 as hex
     * Blake2s.init(33, "");  // throws Blake2Error.BadOutputLength
     * ```
     *
     * @since 1.0.0
     */

    init(outLen: usize, key: readonly u8[]): Blake2s | Error {
        if (outLen < 1 || outLen > 32) throw Blake2Error.BadOutputLength;
        if (key.len > 32) throw Blake2Error.BadKeyLength;

        return startBlake2s(outLen, key);
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * It compresses a full block only when more bytes arrive after it,
     * so the last block always waits for {@link Blake2s.finish}.
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = try Blake2s.init(32, "");
     * hash.update("abc");
     * let out: u8[32] = undefined;
     * try hash.finish(&out); // 508c5e8c...86675982 as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Blake2s, bytes: readonly u8[]): void {
        let at: usize = 0;
        while (at < bytes.len) {
            if (this.used == 64) {
                this.count +%= 64;
                if (this.count < 64) this.countHigh +%= 1;
                compressBlake2s(&this.state, &this.block, this.count, this.countHigh, false);
                this.used = 0;
            }
            const take = 64 - this.used < bytes.len - at ? 64 - this.used : bytes.len - at;
            for (const i of 0..take) this.block[this.used + i] = bytes[at + i];
            this.used += take;
            at += take;
        }
    }

    /**
     * Writes the digest of every byte added so far.
     *
     * @param out - The buffer for the digest, at least `outLen` bytes long
     * @returns The first `outLen` bytes of `out`, which hold the digest
     * @throws Blake2Error.ShortBuffer when `out` is shorter than `outLen`
     *
     * @remarks
     * It compresses the last block of a copy and leaves the state alone,
     * so more bytes may follow and a later call covers them too.
     * It writes nothing past the first `outLen` bytes of `out`.
     *
     * @example
     * ```hx
     * let hash = try Blake2s.init(28, "");
     * hash.update("abc");
     * let out: u8[28] = undefined;
     * try hash.finish(&out); // 0b033fc2...407fbd55 as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Blake2s, out: u8[]): u8[] | Error {
        if (out.len < this.outLen) throw Blake2Error.ShortBuffer;
        const full = outputBlake2s(this);
        for (const i of 0..this.outLen) out[i] = full[i];

        return out[0..this.outLen];
    }
}

/**
 * Computes the 64-byte BLAKE2b digest of bytes, without a key.
 *
 * @param bytes - The bytes
 * @returns Their 64-byte digest
 *
 * @remarks
 * It's BLAKE2b-512 of RFC 7693, the same as `hashlib.blake2b` with its defaults.
 * Use it when all the bytes are at hand and the full output is wanted,
 * and {@link Blake2b} for pieces, a shorter output, or a key.
 *
 * @example
 * ```hx
 * const digest = blake2b("abc");
 * let out: u8[128] = undefined;
 * try encodeHex(&digest, &out); // "ba80a53f981c4d0d...dbf1925ab92386edd4009923"
 * ```
 *
 * @since 1.0.0
 */

export function blake2b(bytes: readonly u8[]): u8[64] {
    let hash = startBlake2b(64, "");
    hash.update(bytes);

    return outputBlake2b(&hash);
}

/**
 * Computes the 32-byte BLAKE2s digest of bytes, without a key.
 *
 * @param bytes - The bytes
 * @returns Their 32-byte digest
 *
 * @remarks
 * It's BLAKE2s-256 of RFC 7693, the same as `hashlib.blake2s` with its defaults.
 * Use it when all the bytes are at hand and the full output is wanted,
 * and {@link Blake2s} for pieces, a shorter output, or a key.
 *
 * @example
 * ```hx
 * const digest = blake2s("abc");
 * let out: u8[64] = undefined;
 * try encodeHex(&digest, &out); // "508c5e8c327c14e2...4d999b4c86675982"
 * ```
 *
 * @since 1.0.0
 */

export function blake2s(bytes: readonly u8[]): u8[32] {
    let hash = startBlake2s(32, "");
    hash.update(bytes);

    return outputBlake2s(&hash);
}
