/**
 * Imports
 */

import { Sha224InitialState, Sha256InitialState, Sha256RoundConstants } from "@sha256/constants/sha256.constant";

/**
 * Rotates a 32-bit word to the right.
 *
 * @param x - The word
 * @param n - The number of bits, from 1 to 31
 * @returns The word with its low `n` bits moved to the top
 *
 * @remarks
 * A count of 0 would shift `x` left by 32, so only the nonzero counts of the SHA-256 rounds may reach it.
 *
 * @since 1.0.0
 */

function rotr(x: u32, n: u32): u32 {
    return (x >> n) | (x << (32 - n));
}

/**
 * Runs the 64 rounds of SHA-256 on one block and adds the result to the state.
 *
 * @param state - The eight words of the running hash
 * @param block - The 64 bytes of the block
 *
 * @remarks
 * It expands the 16 big-endian words of the block to 64 words and mixes them into the state,
 * with every addition wrapping as FIPS 180-4 requires.
 * SHA-224 runs the same rounds and differs only in its initial state and the length of its digest.
 *
 * @since 1.0.0
 */

function compress(state: *u32[8], block: readonly u8[]): void {
    let w: u32[64] = undefined;
    for (const i of 0..16) {
        w[i] = ((block[i * 4] as u32) << 24) | ((block[i * 4 + 1] as u32) << 16) |
               ((block[i * 4 + 2] as u32) << 8) | (block[i * 4 + 3] as u32);
    }
    for (const i of 16..64) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
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
    for (const i of 0..64) {
        const big1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const choose = (e & f) ^ (~e & g);
        const t1 = h +% big1 +% choose +% Sha256RoundConstants[i] +% w[i];
        const big0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
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
 * It feeds the padding of FIPS 180-4 to a copy: a `0x80` byte, zeros up to byte 56 of a block,
 * and the length in bits as 8 big-endian bytes.
 * Working on a copy is what lets {@link Sha256.finish} and {@link Sha224.finish} leave the hash usable.
 *
 * @since 1.0.0
 */

function finalState(hash: readonly *Sha256): u32[8] {
    let copy = *hash;
    const bits = copy.length *% 8;
    const one: u8[1] = [0x80];
    const zero: u8[1] = [0];
    copy.update(&one);
    while (copy.used != 56) copy.update(&zero);
    let length: u8[8] = undefined;
    for (const i of 0..8) length[i] = @truncate(u8, bits >> (56 - i * 8) as u64);
    copy.update(&length);

    return copy.state;
}

/**
 * A running SHA-256 that takes its bytes in pieces.
 *
 * @remarks
 * It follows FIPS 180-4 and buffers up to 63 bytes, compressing each block of 64 as soon as it fills.
 * Reach for it over {@link sha256} when the bytes arrive in chunks, as from a file or a stream.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 * It allocates nothing and keeps all of its state in its own fields.
 *
 * @example
 * ```hx
 * let hash = Sha256.init();
 * hash.update("a");
 * hash.update("bc");
 * hash.finish(); // ba7816bf...f20015ad as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Sha256 {
    /**
     * The eight words of the running hash.
     *
     * @remarks
     * Each full block updates them, and {@link Sha256.finish} writes the padded result out big-endian.
     *
     * @example
     * ```hx
     * Sha256.init().state[0]; // 0x6A09E667
     * ```
     *
     * @since 1.0.0
     */

    state: u32[8],

    /**
     * The number of bytes added so far.
     *
     * @remarks
     * It wraps at 2 to the power of 64, and the padding stores it in bits.
     *
     * @example
     * ```hx
     * let hash = Sha256.init();
     * hash.update("abc");
     * hash.length; // 3
     * ```
     *
     * @since 1.0.0
     */

    length: u64,

    /**
     * The block of 64 bytes that fills up before each compression.
     *
     * @remarks
     * Only its first `used` bytes hold input, and the rest is left over from earlier blocks or undefined.
     *
     * @example
     * ```hx
     * let hash = Sha256.init();
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
     * It stays below 64 between calls, since a full block compresses at once.
     *
     * @example
     * ```hx
     * let hash = Sha256.init();
     * hash.update("abc");
     * hash.used; // 3
     * ```
     *
     * @since 1.0.0
     */

    used: usize,

    /**
     * Starts a SHA-256 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the digest of no bytes.
     *
     * @example
     * ```hx
     * Sha256.init().finish(); // e3b0c442...7852b855 as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Sha256 {
        return Sha256 { state: Sha256InitialState, length: 0, block: undefined, used: 0 };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * It copies the bytes into `block` and compresses each block of 64 that fills.
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = Sha256.init();
     * hash.update("abc");
     * hash.finish(); // ba7816bf...f20015ad as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Sha256, bytes: readonly u8[]): void {
        this.length +%= bytes.len as u64;
        let at: usize = 0;
        while (at < bytes.len) {
            const take = 64 - this.used < bytes.len - at ? 64 - this.used : bytes.len - at;
            for (const i of 0..take) this.block[this.used + i] = bytes[at + i];
            this.used += take;
            at += take;
            if (this.used == 64) {
                compress(&this.state, &this.block);
                this.used = 0;
            }
        }
    }

    /**
     * Tells the digest of every byte added so far.
     *
     * @returns The 32-byte digest
     *
     * @remarks
     * It pads a copy and leaves the state alone, so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let hash = Sha256.init();
     * hash.update("a");
     * hash.finish(); // ca978112...afee48bb as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Sha256): u8[32] {
        const state = finalState(this);
        let digest: u8[32] = undefined;
        for (const word, i of state) {
            digest[i * 4] = @truncate(u8, word >> 24);
            digest[i * 4 + 1] = @truncate(u8, word >> 16);
            digest[i * 4 + 2] = @truncate(u8, word >> 8);
            digest[i * 4 + 3] = @truncate(u8, word);
        }

        return digest;
    }
}

/**
 * A running SHA-224 that takes its bytes in pieces.
 *
 * @remarks
 * It's SHA-256 with its own initial state and the digest cut to 28 bytes, as FIPS 180-4 defines it.
 * Reach for it over {@link sha224} when the bytes arrive in chunks.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 *
 * @example
 * ```hx
 * let hash = Sha224.init();
 * hash.update("a");
 * hash.update("bc");
 * hash.finish(); // 23097d22...e36c9da7 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Sha224 {
    /**
     * The SHA-256 rounds that do the work, started from the SHA-224 state.
     *
     * @remarks
     * {@link Sha224.update} feeds it, and {@link Sha224.finish} keeps the first seven words of its final state.
     *
     * @example
     * ```hx
     * Sha224.init().core.state[0]; // 0xC1059ED8
     * ```
     *
     * @since 1.0.0
     */

    core: Sha256,

    /**
     * Starts a SHA-224 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the digest of no bytes.
     *
     * @example
     * ```hx
     * Sha224.init().finish(); // d14a028c...c5b3e42f as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Sha224 {
        return Sha224 { core: Sha256 { state: Sha224InitialState, length: 0, block: undefined, used: 0 } };
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
     * let hash = Sha224.init();
     * hash.update("abc");
     * hash.finish(); // 23097d22...e36c9da7 as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Sha224, bytes: readonly u8[]): void {
        this.core.update(bytes);
    }

    /**
     * Tells the digest of every byte added so far.
     *
     * @returns The 28-byte digest
     *
     * @remarks
     * It pads a copy and leaves the state alone, so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let hash = Sha224.init();
     * hash.update("a");
     * hash.finish(); // abd37534...78d6d6d5 as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Sha224): u8[28] {
        const state = finalState(&this.core);
        let digest: u8[28] = undefined;
        for (const i of 0..7) {
            const word = state[i];
            digest[i * 4] = @truncate(u8, word >> 24);
            digest[i * 4 + 1] = @truncate(u8, word >> 16);
            digest[i * 4 + 2] = @truncate(u8, word >> 8);
            digest[i * 4 + 3] = @truncate(u8, word);
        }

        return digest;
    }
}
