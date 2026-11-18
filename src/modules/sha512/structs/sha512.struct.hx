/**
 * Imports
 */

import { Sha384InitialState, Sha512InitialState, Sha512RoundConstants } from "@sha512/constants/sha512.constant";

/**
 * Rotates a 64-bit word to the right.
 *
 * @param x - The word
 * @param n - The number of bits, from 1 to 63
 * @returns The word with its low `n` bits moved to the top
 *
 * @remarks
 * A count of 0 would shift `x` left by 64, so only the nonzero counts of the SHA-512 rounds may reach it.
 *
 * @since 1.0.0
 */

function rotr(x: u64, n: u64): u64 {
    return (x >> n) | (x << (64 - n));
}

/**
 * Runs the 80 rounds of SHA-512 on one block and adds the result to the state.
 *
 * @param state - The eight words of the running hash
 * @param block - The 128 bytes of the block
 *
 * @remarks
 * It expands the 16 big-endian words of the block to 80 words and mixes them into the state,
 * with every addition wrapping as FIPS 180-4 requires.
 * SHA-384 runs the same rounds and differs only in its initial state and the length of its digest.
 *
 * @since 1.0.0
 */

function compress(state: *u64[8], block: readonly u8[]): void {
    let w: u64[80] = undefined;
    for (const i of 0..16) {
        let word: u64 = 0;
        for (const j of 0..8) word = (word << 8) | (block[i * 8 + j] as u64);
        w[i] = word;
    }
    for (const i of 16..80) {
        const s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
        const s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] +% s0 +% w[i - 7] +% s1;
    }

    let a = state[0];
    let b = state[1];
    let c = state[2];
    let d = state[3];
    let e = state[4];
    let f = state[5];
    let g = state[6];
    let h = state[7];
    for (const i of 0..80) {
        const big1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
        const choose = (e & f) ^ (~e & g);
        const t1 = h +% big1 +% choose +% Sha512RoundConstants[i] +% w[i];
        const big0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        const t2 = big0 +% majority;
        h = g;
        g = f;
        f = e;
        e = d +% t1;
        d = c;
        c = b;
        b = a;
        a = t1 +% t2;
    }

    state[0] +%= a;
    state[1] +%= b;
    state[2] +%= c;
    state[3] +%= d;
    state[4] +%= e;
    state[5] +%= f;
    state[6] +%= g;
    state[7] +%= h;
}

/**
 * Pads a copy of a hash and returns the state that its digest comes from.
 *
 * @param hash - The hash to finish
 * @returns The eight words of the final state
 *
 * @remarks
 * It feeds the padding of FIPS 180-4 to a copy: a `0x80` byte, zeros up to byte 112 of a block,
 * and the length in bits as 16 big-endian bytes.
 * The byte count is 64 bits wide, so the top 64 bits of the length are the 3 bits that shifting it by 3 pushes out.
 * Working on a copy is what lets {@link Sha512.finish} and {@link Sha384.finish} leave the hash usable.
 *
 * @since 1.0.0
 */

function finalState(hash: readonly *Sha512): u64[8] {
    let copy = *hash;
    const high = copy.length >> 61;
    const low = copy.length << 3;
    const one: u8[1] = [0x80];
    const zero: u8[1] = [0];
    copy.update(&one);
    while (copy.used != 112) copy.update(&zero);
    let length: u8[16] = undefined;
    for (const i of 0..8) {
        length[i] = @truncate(u8, high >> (56 - i * 8) as u64);
        length[i + 8] = @truncate(u8, low >> (56 - i * 8) as u64);
    }
    copy.update(&length);

    return copy.state;
}

/**
 * Writes the first words of a final state out as big-endian bytes.
 *
 * @param state - The final state
 * @param out - The buffer for the digest, whose length is a multiple of 8
 *
 * @remarks
 * It writes `out.len / 8` words, so SHA-512 passes 64 bytes and SHA-384 passes 48.
 *
 * @since 1.0.0
 */

function storeWords(state: readonly u64[], out: u8[]): void {
    for (const i of 0..out.len / 8) {
        const word = state[i];
        for (const j of 0..8) out[i * 8 + j] = @truncate(u8, word >> (56 - j * 8) as u64);
    }
}

/**
 * A running SHA-512 that takes its bytes in pieces.
 *
 * @remarks
 * It follows FIPS 180-4 and buffers up to 127 bytes, compressing each block of 128 as soon as it fills.
 * Reach for it over {@link sha512} when the bytes arrive in chunks, as from a file or a stream.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 * Ed25519 hashes its keys and messages with it.
 *
 * @example
 * ```hx
 * let hash = Sha512.init();
 * hash.update("a");
 * hash.update("bc");
 * hash.finish(); // ddaf35a1...a54ca49f as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Sha512 {
    /**
     * The eight words of the running hash.
     *
     * @remarks
     * Each full block updates them, and {@link Sha512.finish} writes the padded result out big-endian.
     *
     * @example
     * ```hx
     * Sha512.init().state[0]; // 0x6A09E667F3BCC908
     * ```
     *
     * @since 1.0.0
     */

    state: u64[8],

    /**
     * The number of bytes added so far.
     *
     * @remarks
     * It wraps at 2 to the power of 64, which is far beyond any input that a program can hash.
     * The padding stores it as a 128-bit count of bits.
     *
     * @example
     * ```hx
     * let hash = Sha512.init();
     * hash.update("abc");
     * hash.length; // 3
     * ```
     *
     * @since 1.0.0
     */

    length: u64,

    /**
     * The block of 128 bytes that fills up before each compression.
     *
     * @remarks
     * Only its first `used` bytes hold input, and the rest is left over from earlier blocks or undefined.
     *
     * @example
     * ```hx
     * let hash = Sha512.init();
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
     * It stays below 128 between calls, since a full block compresses at once.
     *
     * @example
     * ```hx
     * let hash = Sha512.init();
     * hash.update("abc");
     * hash.used; // 3
     * ```
     *
     * @since 1.0.0
     */

    used: usize,

    /**
     * Starts a SHA-512 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the digest of no bytes.
     *
     * @example
     * ```hx
     * Sha512.init().finish(); // cf83e135...f927da3e as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Sha512 {
        return Sha512 { state: Sha512InitialState, length: 0, block: undefined, used: 0 };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * It copies the bytes into `block` and compresses each block of 128 that fills.
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = Sha512.init();
     * hash.update("abc");
     * hash.finish(); // ddaf35a1...a54ca49f as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Sha512, bytes: readonly u8[]): void {
        this.length +%= bytes.len as u64;
        let at: usize = 0;
        while (at < bytes.len) {
            const take = 128 - this.used < bytes.len - at ? 128 - this.used : bytes.len - at;
            for (const i of 0..take) this.block[this.used + i] = bytes[at + i];
            this.used += take;
            at += take;
            if (this.used == 128) {
                compress(&this.state, &this.block);
                this.used = 0;
            }
        }
    }

    /**
     * Tells the digest of every byte added so far.
     *
     * @returns The 64-byte digest
     *
     * @remarks
     * It pads a copy and leaves the state alone, so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let hash = Sha512.init();
     * hash.update("a");
     * hash.finish(); // 1f40fc92...52fe9a75 as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Sha512): u8[64] {
        const state = finalState(this);
        let digest: u8[64] = undefined;
        storeWords(&state, &digest);

        return digest;
    }
}

/**
 * A running SHA-384 that takes its bytes in pieces.
 *
 * @remarks
 * It's SHA-512 with its own initial state and the digest cut to 48 bytes, as FIPS 180-4 defines it.
 * Reach for it over {@link sha384} when the bytes arrive in chunks.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 *
 * @example
 * ```hx
 * let hash = Sha384.init();
 * hash.update("a");
 * hash.update("bc");
 * hash.finish(); // cb00753f...34c825a7 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Sha384 {
    /**
     * The SHA-512 rounds that do the work, started from the SHA-384 state.
     *
     * @remarks
     * {@link Sha384.update} feeds it, and {@link Sha384.finish} keeps the first six words of its final state.
     *
     * @example
     * ```hx
     * Sha384.init().core.state[0]; // 0xCBBB9D5DC1059ED8
     * ```
     *
     * @since 1.0.0
     */

    core: Sha512,

    /**
     * Starts a SHA-384 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the digest of no bytes.
     *
     * @example
     * ```hx
     * Sha384.init().finish(); // 38b060a7...4898b95b as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Sha384 {
        return Sha384 { core: Sha512 { state: Sha384InitialState, length: 0, block: undefined, used: 0 } };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = Sha384.init();
     * hash.update("abc");
     * hash.finish(); // cb00753f...34c825a7 as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Sha384, bytes: readonly u8[]): void {
        this.core.update(bytes);
    }

    /**
     * Tells the digest of every byte added so far.
     *
     * @returns The 48-byte digest
     *
     * @remarks
     * It pads a copy and leaves the state alone, so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let hash = Sha384.init();
     * hash.update("a");
     * hash.finish(); // 54a59b9f...d3145f31 as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Sha384): u8[48] {
        const state = finalState(&this.core);
        let digest: u8[48] = undefined;
        storeWords(&state, &digest);

        return digest;
    }
}
