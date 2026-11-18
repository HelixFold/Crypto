/**
 * Imports
 */

import { Poly1305Error } from "@poly1305/errors/poly1305.error";

/**
 * The mask of one 26-bit limb.
 *
 * @remarks
 * The accumulator and `r` are each split into five limbs of 26 bits, the layout of poly1305-donna's 32-bit code.
 * A product of two limbs then fits in 52 bits,
 * so a sum of five products stays far below 2 to the power of 64.
 *
 * @since 1.0.0
 */

const Mask26: u64 = 0x3FF_FFFF;

/**
 * The bit that every full block adds above its 128 bits, in the top limb.
 *
 * @remarks
 * Poly1305 appends a `1` byte to each block, which for a 16-byte block is bit 128 of the number,
 * or bit 24 of the fifth limb.
 * The last partial block appends that byte itself and passes 0 here instead.
 *
 * @since 1.0.0
 */

const HighBit: u64 = 0x100_0000;

/**
 * Reads a little-endian 32-bit word from four bytes, widened to 64 bits.
 *
 * @param bytes - The bytes
 * @param at - The index of the lowest byte
 * @returns The word
 *
 * @remarks
 * The limbs overlap byte boundaries, so the code reads the words at offsets 0, 3, 6, 9, and 12 and shifts each one.
 * The caller makes sure that the four bytes from `at` on exist.
 *
 * @since 1.0.0
 */

function load32(bytes: readonly u8[], at: usize): u64 {
    return (bytes[at] as u64) | ((bytes[at + 1] as u64) << 8) | ((bytes[at + 2] as u64) << 16) |
        ((bytes[at + 3] as u64) << 24);
}

/**
 * Writes the low 32 bits of a word as four little-endian bytes.
 *
 * @param out - The buffer
 * @param at - The index of the lowest byte
 * @param word - The word, whose bits above 32 are ignored
 *
 * @remarks
 * The final addition carries into bit 32 of the word, and dropping that carry is the reduction modulo 2 to the 128.
 *
 * @since 1.0.0
 */

function store32(out: u8[], at: usize, word: u64): void {
    out[at] = @truncate(u8, word);
    out[at + 1] = @truncate(u8, word >> 8);
    out[at + 2] = @truncate(u8, word >> 16);
    out[at + 3] = @truncate(u8, word >> 24);
}

/**
 * Adds one 16-byte block to the accumulator and multiplies by `r`, modulo 2 to the 130 minus 5.
 *
 * @param h - The five limbs of the accumulator, updated in place
 * @param r - The five limbs of the clamped key half `r`
 * @param block - The 16 bytes of the block
 * @param high - {@link HighBit} for a full block, or 0 for the padded last block
 *
 * @remarks
 * It's the block step of poly1305-donna's 32-bit code, with every limb held in a `u64`.
 * The limbs of `r` multiplied by 5 fold the part of the product above 2 to the 130 back into the low limbs,
 * since 2 to the 130 is 5 modulo the prime.
 * A carry pass then leaves every limb at 26 bits, except that the second may hold one more.
 * Each sum of products stays below 2 to the 57, so no addition or multiplication here can overflow.
 * Every step is the same for every input, with no branch and no index that depends on the key or the message.
 *
 * @since 1.0.0
 */

function absorb(h: u64[], r: readonly u64[], block: readonly u8[], high: u64): void {
    const r0 = r[0];
    const r1 = r[1];
    const r2 = r[2];
    const r3 = r[3];
    const r4 = r[4];
    const s1 = r1 * 5;
    const s2 = r2 * 5;
    const s3 = r3 * 5;
    const s4 = r4 * 5;

    const h0 = h[0] + (load32(block, 0) & Mask26);
    const h1 = h[1] + ((load32(block, 3) >> 2) & Mask26);
    const h2 = h[2] + ((load32(block, 6) >> 4) & Mask26);
    const h3 = h[3] + ((load32(block, 9) >> 6) & Mask26);
    const h4 = h[4] + ((load32(block, 12) >> 8) | high);

    const d0 = (h0 * r0) + (h1 * s4) + (h2 * s3) + (h3 * s2) + (h4 * s1);
    let d1 = (h0 * r1) + (h1 * r0) + (h2 * s4) + (h3 * s3) + (h4 * s2);
    let d2 = (h0 * r2) + (h1 * r1) + (h2 * r0) + (h3 * s4) + (h4 * s3);
    let d3 = (h0 * r3) + (h1 * r2) + (h2 * r1) + (h3 * r0) + (h4 * s4);
    let d4 = (h0 * r4) + (h1 * r3) + (h2 * r2) + (h3 * r1) + (h4 * r0);

    let carry = d0 >> 26;
    h[0] = d0 & Mask26;
    d1 += carry;
    carry = d1 >> 26;
    h[1] = d1 & Mask26;
    d2 += carry;
    carry = d2 >> 26;
    h[2] = d2 & Mask26;
    d3 += carry;
    carry = d3 >> 26;
    h[3] = d3 & Mask26;
    d4 += carry;
    carry = d4 >> 26;
    h[4] = d4 & Mask26;
    h[0] += carry * 5;
    carry = h[0] >> 26;
    h[0] &= Mask26;
    h[1] += carry;
}

/**
 * A running Poly1305 that takes its message in pieces.
 *
 * @remarks
 * It follows section 2.5 of RFC 8439, with the arithmetic of poly1305-donna's 32-bit code:
 * five 26-bit limbs in `u64` words, so no 128-bit type is needed.
 * Poly1305 alone is a one-time authenticator.
 * A key must never authenticate more than one message,
 * since two tags under the same key let an attacker forge tags for other messages.
 * ChaCha20-Poly1305 derives a fresh key for every nonce, which is the safe way to use it.
 * The time depends only on the length of the message, never on the key or the bytes.
 * Check a tag with {@link timingSafeEqual}, never with an ordinary comparison.
 * Reach for it over {@link poly1305} when the message arrives in chunks.
 *
 * @example
 * ```hx
 * // the key 85d6be78...4149f51b of RFC 8439, section 2.5.2
 * let mac = try Poly1305.init(&key);
 * mac.update("Cryptographic Forum ");
 * mac.update("Research Group");
 * mac.finish(); // a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9
 * ```
 *
 * @since 1.0.0
 */

export struct Poly1305 {
    /**
     * The clamped first half of the key, as five 26-bit limbs.
     *
     * @remarks
     * {@link Poly1305.init} clears the bits that RFC 8439 says to clamp while splitting the bytes into limbs.
     *
     * @example
     * ```hx
     * mac.r[0]; // the low 26 bits of r
     * ```
     *
     * @since 1.0.0
     */

    r: u64[5],

    /**
     * The accumulator, as five 26-bit limbs, partly reduced modulo 2 to the 130 minus 5.
     *
     * @remarks
     * It starts at zero, and each full block of the message adds to it and multiplies it by `r`.
     *
     * @example
     * ```hx
     * Poly1305.init(&key).h[0]; // 0
     * ```
     *
     * @since 1.0.0
     */

    h: u64[5],

    /**
     * The second half of the key, as four little-endian 32-bit words.
     *
     * @remarks
     * {@link Poly1305.finish} adds it to the reduced accumulator modulo 2 to the 128.
     *
     * @example
     * ```hx
     * mac.pad[0]; // the low 32 bits of s
     * ```
     *
     * @since 1.0.0
     */

    pad: u64[4],

    /**
     * The bytes of a block that has not filled yet.
     *
     * @remarks
     * Only the first `used` bytes hold message bytes.
     *
     * @example
     * ```hx
     * let mac = try Poly1305.init(&key);
     * mac.update("abc");
     * mac.buffer[0]; // 0x61
     * ```
     *
     * @since 1.0.0
     */

    buffer: u8[16],

    /**
     * The number of bytes waiting in `buffer`.
     *
     * @remarks
     * It stays below 16 between calls, since a full block goes into the accumulator at once.
     *
     * @example
     * ```hx
     * let mac = try Poly1305.init(&key);
     * mac.update("abc");
     * mac.used; // 3
     * ```
     *
     * @since 1.0.0
     */

    used: usize,

    /**
     * Starts a Poly1305 under a one-time key.
     *
     * @param key - The 32-byte one-time key, `r` then `s`
     * @returns The MAC, ready for the message
     * @throws Poly1305Error.BadKeyLength when the key is not 32 bytes
     *
     * @remarks
     * It clamps `r` as section 2.5 of RFC 8439 says, by masking the limbs with fixed constants.
     * Use each key for one message only.
     *
     * @example
     * ```hx
     * const mac = try Poly1305.init(&key);
     * mac.finish(); // the last 16 bytes of the key, the tag of an empty message
     * ```
     *
     * @since 1.0.0
     */

    init(key: readonly u8[]): Poly1305 | Error {
        if (key.len != 32) throw Poly1305Error.BadKeyLength;

        let r: u64[5] = undefined;
        r[0] = load32(key, 0) & 0x3FF_FFFF;
        r[1] = (load32(key, 3) >> 2) & 0x3FF_FF03;
        r[2] = (load32(key, 6) >> 4) & 0x3FF_C0FF;
        r[3] = (load32(key, 9) >> 6) & 0x3F0_3FFF;
        r[4] = (load32(key, 12) >> 8) & 0x00F_FFFF;
        let h: u64[5] = undefined;
        for (const _, i of h) h[i] = 0;
        let pad: u64[4] = undefined;
        for (const i of 0..4) pad[i] = load32(key, 16 + 4 * i);
        let buffer: u8[16] = undefined;
        for (const _, i of buffer) buffer[i] = 0;

        return Poly1305 { r, h, pad, buffer, used: 0 };
    }

    /**
     * Adds message bytes.
     *
     * @param bytes - The next bytes of the message
     *
     * @remarks
     * It tops up `buffer` first, then takes every full block straight from `bytes`, and keeps the rest.
     * Splitting the message at any point gives the same tag as adding it at once.
     * An empty slice changes nothing.
     *
     * @example
     * ```hx
     * let mac = try Poly1305.init(&key);
     * mac.update("Cryptographic Forum Research Group");
     * mac.finish(); // a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Poly1305, bytes: readonly u8[]): void {
        let at: usize = 0;
        if (this.used > 0) {
            const room = 16 - this.used;
            const take = room < bytes.len ? room : bytes.len;
            for (const i of 0..take) this.buffer[this.used + i] = bytes[i];
            this.used += take;
            at = take;
            if (this.used < 16) return;
            absorb(&this.h, &this.r, &this.buffer, HighBit);
            this.used = 0;
        }
        while (bytes.len - at >= 16) {
            absorb(&this.h, &this.r, bytes[at..at + 16], HighBit);
            at += 16;
        }
        for (const i of 0..bytes.len - at) this.buffer[i] = bytes[at + i];
        this.used = bytes.len - at;
    }

    /**
     * Tells the tag of the message so far.
     *
     * @returns The 16-byte tag
     *
     * @remarks
     * It works on a copy of the accumulator, so more bytes may follow and a later call covers them too.
     * A partial last block gets a `1` byte and zeros appended, as RFC 8439 says.
     * The final reduction subtracts the prime with a mask rather than a branch,
     * and adding `s` modulo 2 to the 128 gives the tag.
     *
     * @example
     * ```hx
     * let mac = try Poly1305.init(&key);
     * mac.update("Cryptographic Forum Research Group");
     * mac.finish(); // a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Poly1305): u8[16] {
        let h: u64[5] = this.h;
        if (this.used > 0) {
            let last: u8[16] = undefined;
            for (const _, i of last) last[i] = 0;
            for (const i of 0..this.used) last[i] = this.buffer[i];
            last[this.used] = 1;
            absorb(&h, &this.r, &last, 0);
        }

        // Carry fully, so every limb holds 26 bits and h is below 2 to the 130 plus a little.
        let h0 = h[0];
        let h1 = h[1];
        let h2 = h[2];
        let h3 = h[3];
        let h4 = h[4];
        let carry = h1 >> 26;
        h1 &= Mask26;
        h2 += carry;
        carry = h2 >> 26;
        h2 &= Mask26;
        h3 += carry;
        carry = h3 >> 26;
        h3 &= Mask26;
        h4 += carry;
        carry = h4 >> 26;
        h4 &= Mask26;
        h0 += carry * 5;
        carry = h0 >> 26;
        h0 &= Mask26;
        h1 += carry;

        // g = h + 5 - 2^130, which is h - p. Its top limb wraps below zero exactly when h < p.
        let g0 = h0 + 5;
        carry = g0 >> 26;
        g0 &= Mask26;
        let g1 = h1 + carry;
        carry = g1 >> 26;
        g1 &= Mask26;
        let g2 = h2 + carry;
        carry = g2 >> 26;
        g2 &= Mask26;
        let g3 = h3 + carry;
        carry = g3 >> 26;
        g3 &= Mask26;
        const g4 = (h4 + carry) -% 0x400_0000;

        // All ones when g4 did not wrap, so h >= p and g replaces h. Zero otherwise.
        const takeG = (g4 >> 63) -% 1;
        const keepH = ~takeG;
        h0 = (h0 & keepH) | (g0 & takeG);
        h1 = (h1 & keepH) | (g1 & takeG);
        h2 = (h2 & keepH) | (g2 & takeG);
        h3 = (h3 & keepH) | (g3 & takeG);
        h4 = (h4 & keepH) | (g4 & takeG);

        // Pack the 130 bits into four 32-bit words, dropping bits 128 and up, then add s.
        const w0 = (h0 | (h1 << 26)) & 0xFFFF_FFFF;
        const w1 = ((h1 >> 6) | (h2 << 20)) & 0xFFFF_FFFF;
        const w2 = ((h2 >> 12) | (h3 << 14)) & 0xFFFF_FFFF;
        const w3 = ((h3 >> 18) | (h4 << 8)) & 0xFFFF_FFFF;
        let tag: u8[16] = undefined;
        let sum = w0 + this.pad[0];
        store32(&tag, 0, sum);
        sum = w1 + this.pad[1] + (sum >> 32);
        store32(&tag, 4, sum);
        sum = w2 + this.pad[2] + (sum >> 32);
        store32(&tag, 8, sum);
        sum = w3 + this.pad[3] + (sum >> 32);
        store32(&tag, 12, sum);
        return tag;
    }
}
