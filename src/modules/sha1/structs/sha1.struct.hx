/**
 * The five words that the state of every new SHA-1 starts from.
 *
 * @remarks
 * FIPS 180-4 fixes them, and MD5 starts from the same first four words.
 *
 * @since 1.0.0
 */

const Sha1InitialState: u32[5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/**
 * Rotates a 32-bit word to the left.
 *
 * @param x - The word
 * @param n - The number of bits, from 1 to 31
 * @returns The word with its high `n` bits moved to the bottom
 *
 * @remarks
 * A count of 0 would shift `x` right by 32, so only the nonzero counts of the SHA-1 rounds may reach it.
 *
 * @since 1.0.0
 */

function rotl(x: u32, n: u32): u32 {
    return (x << n) | (x >> (32 - n));
}

/**
 * Runs the 80 steps of SHA-1 on one block and adds the result to the state.
 *
 * @param state - The five words of the running hash
 * @param block - The 64 bytes of the block
 *
 * @remarks
 * It expands the 16 big-endian words of the block to 80 words.
 * Each group of 20 steps uses its own mixing function and constant, as FIPS 180-4 lists them.
 * Every addition wraps.
 *
 * @since 1.0.0
 */

function compress(state: *u32[5], block: readonly u8[]): void {
    let w: u32[80] = undefined;
    for (const i of 0..16) {
        w[i] = ((block[i * 4] as u32) << 24) | ((block[i * 4 + 1] as u32) << 16) |
               ((block[i * 4 + 2] as u32) << 8) | (block[i * 4 + 3] as u32);
    }
    for (const i of 16..80) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    let a = state[0];
    let b = state[1];
    let c = state[2];
    let d = state[3];
    let e = state[4];
    for (const i of 0..80) {
        let mix: u32 = 0;
        let constant: u32 = 0;
        if (i < 20) {
            mix = (b & c) | (~b & d);
            constant = 0x5a827999;
        } else if (i < 40) {
            mix = b ^ c ^ d;
            constant = 0x6ed9eba1;
        } else if (i < 60) {
            mix = (b & c) | (b & d) | (c & d);
            constant = 0x8f1bbcdc;
        } else {
            mix = b ^ c ^ d;
            constant = 0xca62c1d6;
        }
        const next = rotl(a, 5) +% mix +% e +% constant +% w[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = next;
    }

    state[0] +%= a;
    state[1] +%= b;
    state[2] +%= c;
    state[3] +%= d;
    state[4] +%= e;
}

/**
 * A running SHA-1 that takes its bytes in pieces, for legacy formats only.
 *
 * @remarks
 * SHA-1 is broken for security: anyone can make two inputs with the same digest, as the SHAttered attack showed.
 * Never use it for signatures, certificates, passwords, or anything that an attacker may choose.
 * Use it only where a format fixes it, such as the ids of git objects, and pick SHA-256 or SHA-3 for anything new.
 * It follows FIPS 180-4 and buffers up to 63 bytes, compressing each block of 64 as soon as it fills.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 *
 * @example
 * ```hx
 * let hash = Sha1.init();
 * hash.update("a");
 * hash.update("bc");
 * hash.finish(); // a9993e36...9cd0d89d as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Sha1 {
    /**
     * The five words of the running hash.
     *
     * @remarks
     * Each full block updates them, and {@link Sha1.finish} writes the padded result out big-endian.
     *
     * @example
     * ```hx
     * Sha1.init().state[0]; // 0x67452301
     * ```
     *
     * @since 1.0.0
     */

    state: u32[5],

    /**
     * The number of bytes added so far.
     *
     * @remarks
     * It wraps at 2 to the power of 64, and the padding stores it in bits.
     *
     * @example
     * ```hx
     * let hash = Sha1.init();
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
     * let hash = Sha1.init();
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
     * let hash = Sha1.init();
     * hash.update("abc");
     * hash.used; // 3
     * ```
     *
     * @since 1.0.0
     */

    used: usize,

    /**
     * Starts a SHA-1 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the digest of no bytes.
     *
     * @example
     * ```hx
     * Sha1.init().finish(); // da39a3ee...afd80709 as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Sha1 {
        return Sha1 { state: Sha1InitialState, length: 0, block: undefined, used: 0 };
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
     * let hash = Sha1.init();
     * hash.update("abc");
     * hash.finish(); // a9993e36...9cd0d89d as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Sha1, bytes: readonly u8[]): void {
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
     * @returns The 20-byte digest
     *
     * @remarks
     * It feeds the padding of FIPS 180-4 to a copy: a `0x80` byte, zeros up to byte 56 of a block,
     * and the length in bits as 8 big-endian bytes.
     * It leaves the state alone, so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let hash = Sha1.init();
     * hash.update("a");
     * hash.finish(); // 86f7e437...377667b8 as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Sha1): u8[20] {
        let copy = *this;
        const bits = copy.length *% 8;
        const one: u8[1] = [0x80];
        const zero: u8[1] = [0];
        copy.update(&one);
        while (copy.used != 56) copy.update(&zero);
        let length: u8[8] = undefined;
        for (const i of 0..8) length[i] = @truncate(u8, bits >> (56 - i * 8) as u64);
        copy.update(&length);

        let digest: u8[20] = undefined;
        for (const word, i of copy.state) {
            digest[i * 4] = @truncate(u8, word >> 24);
            digest[i * 4 + 1] = @truncate(u8, word >> 16);
            digest[i * 4 + 2] = @truncate(u8, word >> 8);
            digest[i * 4 + 3] = @truncate(u8, word);
        }

        return digest;
    }
}
