/**
 * Imports
 */

import { Md5Constants, Md5Shifts } from "@md5/constants/md5.constant";

/**
 * The four words that the state of every new MD5 starts from.
 *
 * @remarks
 * RFC 1321 lists them as the bytes `01 23 45 67`, `89 AB CD EF`, `FE DC BA 98`, and `76 54 32 10`,
 * read as little-endian words.
 *
 * @since 1.0.0
 */

const Md5InitialState: u32[4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

/**
 * Rotates a 32-bit word to the left.
 *
 * @param x - The word
 * @param n - The number of bits, from 1 to 31
 * @returns The word with its high `n` bits moved to the bottom
 *
 * @remarks
 * A count of 0 would shift `x` right by 32, so only the nonzero counts of {@link Md5Shifts} may reach it.
 *
 * @since 1.0.0
 */

function rotl(x: u32, n: u32): u32 {
    return (x << n) | (x >> (32 - n));
}

/**
 * Runs the 64 steps of MD5 on one block and adds the result to the state.
 *
 * @param state - The four words of the running hash
 * @param block - The 64 bytes of the block
 *
 * @remarks
 * It reads the block as 16 little-endian words.
 * Each round of 16 steps has its own mixing function and its own order of reading the words, as RFC 1321 lists them.
 * Every addition wraps.
 *
 * @since 1.0.0
 */

function compress(state: *u32[4], block: readonly u8[]): void {
    let m: u32[16] = undefined;
    for (const i of 0..16) {
        m[i] = (block[i * 4] as u32) | ((block[i * 4 + 1] as u32) << 8) |
               ((block[i * 4 + 2] as u32) << 16) | ((block[i * 4 + 3] as u32) << 24);
    }

    let a = state[0];
    let b = state[1];
    let c = state[2];
    let d = state[3];
    for (const i of 0..64) {
        let mix: u32 = 0;
        let word: usize = 0;
        if (i < 16) {
            mix = (b & c) | (~b & d);
            word = i;
        } else if (i < 32) {
            mix = (d & b) | (~d & c);
            word = (5 * i + 1) % 16;
        } else if (i < 48) {
            mix = b ^ c ^ d;
            word = (3 * i + 5) % 16;
        } else {
            mix = c ^ (b | ~d);
            word = (7 * i) % 16;
        }
        const sum = a +% mix +% Md5Constants[i] +% m[word];
        a = d;
        d = c;
        c = b;
        b = b +% rotl(sum, Md5Shifts[i]);
    }

    state[0] +%= a;
    state[1] +%= b;
    state[2] +%= c;
    state[3] +%= d;
}

/**
 * A running MD5 that takes its bytes in pieces, for legacy formats only.
 *
 * @remarks
 * MD5 is broken for security: a laptop finds two inputs with the same digest in seconds.
 * Never use it for signatures, certificates, passwords, or anything that an attacker may choose.
 * Use it only where a format fixes it, such as an old checksum file or a `Content-MD5` header,
 * and pick SHA-256 or SHA-3 for anything new.
 * It follows RFC 1321 and buffers up to 63 bytes, compressing each block of 64 as soon as it fills.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 *
 * @example
 * ```hx
 * let hash = Md5.init();
 * hash.update("a");
 * hash.update("bc");
 * hash.finish(); // 90015098...28e17f72 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Md5 {
    /**
     * The four words of the running hash.
     *
     * @remarks
     * Each full block updates them, and {@link Md5.finish} writes the padded result out little-endian.
     *
     * @example
     * ```hx
     * Md5.init().state[0]; // 0x67452301
     * ```
     *
     * @since 1.0.0
     */

    state: u32[4],

    /**
     * The number of bytes added so far.
     *
     * @remarks
     * It wraps at 2 to the power of 64, and the padding stores it in bits.
     *
     * @example
     * ```hx
     * let hash = Md5.init();
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
     * let hash = Md5.init();
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
     * let hash = Md5.init();
     * hash.update("abc");
     * hash.used; // 3
     * ```
     *
     * @since 1.0.0
     */

    used: usize,

    /**
     * Starts an MD5 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the digest of no bytes.
     *
     * @example
     * ```hx
     * Md5.init().finish(); // d41d8cd9...ecf8427e as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Md5 {
        return Md5 { state: Md5InitialState, length: 0, block: undefined, used: 0 };
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
     * let hash = Md5.init();
     * hash.update("abc");
     * hash.finish(); // 90015098...28e17f72 as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Md5, bytes: readonly u8[]): void {
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
     * @returns The 16-byte digest
     *
     * @remarks
     * It feeds the padding of RFC 1321 to a copy: a `0x80` byte, zeros up to byte 56 of a block,
     * and the length in bits as 8 little-endian bytes.
     * It leaves the state alone, so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let hash = Md5.init();
     * hash.update("a");
     * hash.finish(); // 0cc175b9...69772661 as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Md5): u8[16] {
        let copy = *this;
        const bits = copy.length *% 8;
        const one: u8[1] = [0x80];
        const zero: u8[1] = [0];
        copy.update(&one);
        while (copy.used != 56) copy.update(&zero);
        let length: u8[8] = undefined;
        for (const i of 0..8) length[i] = @truncate(u8, bits >> (i * 8) as u64);
        copy.update(&length);

        let digest: u8[16] = undefined;
        for (const word, i of copy.state) {
            digest[i * 4] = @truncate(u8, word);
            digest[i * 4 + 1] = @truncate(u8, word >> 8);
            digest[i * 4 + 2] = @truncate(u8, word >> 16);
            digest[i * 4 + 3] = @truncate(u8, word >> 24);
        }

        return digest;
    }
}
