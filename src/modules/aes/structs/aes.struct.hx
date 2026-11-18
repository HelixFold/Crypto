/**
 * Imports
 */

import { AesError } from "@aes/errors/aes.error";

/**
 * The round constants of the AES key schedule, indexed from 1.
 *
 * @remarks
 * Entry `i` is 2 to the power of `i - 1` in GF(2^8).
 * FIPS 197 XORs it into the first byte of every `Nk`-th word of the schedule.
 * The index is a word position, never key material, so reading it leaks nothing.
 * AES-128 needs entries 1 to 10, and the longer keys need fewer.
 *
 * @since 1.0.0
 */

const Rcon: u8[11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

/**
 * Builds an all-ones or all-zeros byte from a bit.
 *
 * @param bit - 0 or 1
 * @returns `0xFF` for 1, and `0x00` for 0
 *
 * @remarks
 * It subtracts the bit from zero with wrapping, so selecting by a secret bit needs no branch.
 *
 * @since 1.0.0
 */

function mask(bit: u8): u8 {
    return (0 as u8) -% bit;
}

/**
 * Multiplies a byte by `x` in GF(2^8), the `xtime` of FIPS 197.
 *
 * @param a - The byte
 * @returns The byte shifted left, reduced by the AES polynomial when its top bit was set
 *
 * @remarks
 * The reduction XORs `0x1B` through a mask built from the top bit, rather than branching on it.
 * MixColumns and {@link gfMultiply} both build on it.
 *
 * @since 1.0.0
 */

function xtime(a: u8): u8 {
    return (a << 1) ^ (0x1B & mask(a >> 7));
}

/**
 * Multiplies two bytes in GF(2^8) modulo the AES polynomial.
 *
 * @param a - The first byte
 * @param b - The second byte
 * @returns The product
 *
 * @remarks
 * It's the shift-and-add multiplication, run for all 8 bits of `b` every time.
 * Each bit of `b` selects whether `a` is added through a mask, so neither the time nor the memory access
 * depends on either value.
 *
 * @since 1.0.0
 */

function gfMultiply(a: u8, b: u8): u8 {
    let x = a;
    let y = b;
    let product: u8 = 0;
    for (const _ of 0..8) {
        product ^= x & mask(y & 1);
        x = xtime(x);
        y >>= 1;
    }
    return product;
}

/**
 * Computes the multiplicative inverse of a byte in GF(2^8), with 0 mapping to 0.
 *
 * @param x - The byte
 * @returns `x` to the power of 254
 *
 * @remarks
 * Every nonzero element satisfies `x^255 = 1`, so `x^254` is its inverse, and `0^254` is 0 as AES wants.
 * The fixed addition chain of 7 squarings and 4 multiplications runs the same steps for every input.
 *
 * @since 1.0.0
 */

function inverse(x: u8): u8 {
    const x2 = gfMultiply(x, x);
    const x3 = gfMultiply(x2, x);
    const x6 = gfMultiply(x3, x3);
    const x12 = gfMultiply(x6, x6);
    const x15 = gfMultiply(x12, x3);
    const x30 = gfMultiply(x15, x15);
    const x60 = gfMultiply(x30, x30);
    const x120 = gfMultiply(x60, x60);
    const x240 = gfMultiply(x120, x120);
    const x252 = gfMultiply(x240, x12);
    return gfMultiply(x252, x2);
}

/**
 * Rotates a byte to the left.
 *
 * @param x - The byte
 * @param n - The number of bits, from 1 to 4
 * @returns The byte with its top `n` bits moved to the bottom
 *
 * @remarks
 * The affine step of the S-box uses the counts 1 to 4, so a count of 0, which would shift by 8, never occurs.
 *
 * @since 1.0.0
 */

function rotl8(x: u8, n: u8): u8 {
    return (x << n) | (x >> (8 - n));
}

/**
 * Computes the AES S-box of a byte without a table.
 *
 * @param x - The byte
 * @returns The substituted byte
 *
 * @remarks
 * It's the definition of FIPS 197, section 5.1.1: the inverse in GF(2^8),
 * then the affine map `b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63`.
 * A lookup table indexed by a secret byte leaks the index through the cache,
 * so this costs about 90 masked steps per byte to run in the same time for every input.
 *
 * @since 1.0.0
 */

function subByte(x: u8): u8 {
    const b = inverse(x);
    return b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63;
}

/**
 * Mixes each column of the state with the MixColumns matrix of FIPS 197.
 *
 * @param state - The 16 bytes of the state, column by column
 *
 * @remarks
 * Each output byte is `2a ^ 3b ^ c ^ d` for the right rotation of the column,
 * where doubling is {@link xtime} and tripling is doubling plus the byte itself.
 * Every round but the last runs it.
 *
 * @since 1.0.0
 */

function mixColumns(state: u8[]): void {
    for (const column of 0..4) {
        const at = 4 * column;
        const a0 = state[at];
        const a1 = state[at + 1];
        const a2 = state[at + 2];
        const a3 = state[at + 3];
        state[at] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        state[at + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        state[at + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        state[at + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
    }
}

/**
 * An AES block cipher with its round keys expanded, for encryption only.
 *
 * @remarks
 * It follows FIPS 197 for 128, 192, and 256-bit keys, which run 10, 12, and 14 rounds.
 * It's constant-time: the S-box comes from an inverse in GF(2^8) computed with masks,
 * so no table is ever indexed by the key or the data, and no branch depends on them.
 * That makes it far slower than a table or AES-NI, which is the price of being safe on any target.
 * It only encrypts single blocks, which is all that GCM and other counter modes need.
 * Never use single blocks as a cipher mode, since equal blocks would give equal ciphertext.
 * Use {@link aesGcmSeal} to encrypt messages.
 *
 * @example
 * ```hx
 * const aes = try Aes.init(&key); // the key 00 01 02 ... 0f of FIPS 197, appendix C.1
 * aes.encryptBlock(block);        // 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a
 * ```
 *
 * @since 1.0.0
 */

export struct Aes {
    /**
     * The expanded key schedule, 16 bytes per round key, with the first round key at the start.
     *
     * @remarks
     * AES-256 fills all 240 bytes, while AES-128 and AES-192 use the first 176 and 208 and leave the rest zero.
     *
     * @example
     * ```hx
     * const aes = try Aes.init(&key);
     * aes.roundKeys[0]; // the first byte of the key
     * ```
     *
     * @since 1.0.0
     */

    roundKeys: u8[240],

    /**
     * The number of rounds, which the key length decides.
     *
     * @remarks
     * It's 10 for a 16-byte key, 12 for 24 bytes, and 14 for 32 bytes.
     *
     * @example
     * ```hx
     * const aes = try Aes.init(&key); // a 32-byte key
     * aes.rounds;                     // 14
     * ```
     *
     * @since 1.0.0
     */

    rounds: usize,

    /**
     * Expands a key into the round keys.
     *
     * @param key - The 16, 24, or 32-byte key
     * @returns The cipher, ready to encrypt blocks
     * @throws AesError.BadKeyLength when the key has any other length
     *
     * @remarks
     * It runs the key expansion of FIPS 197, section 5.2, with the table-free S-box,
     * so the key bytes never index memory.
     * The branches depend only on word positions, which are the same for every key of a length.
     *
     * @example
     * ```hx
     * const aes = try Aes.init(&key); // a 16-byte key
     * aes.rounds;                     // 10
     * Aes.init("short");              // throws AesError.BadKeyLength
     * ```
     *
     * @since 1.0.0
     */

    init(key: readonly u8[]): Aes | Error {
        if (key.len != 16 && key.len != 24 && key.len != 32) throw AesError.BadKeyLength;
        const nk = key.len / 4;
        const rounds = nk + 6;

        let w: u8[240] = undefined;
        for (const _, i of w) w[i] = 0;
        for (const byte, i of key) w[i] = byte;
        for (const i of nk..4 * (rounds + 1)) {
            let word: u8[4] = undefined;
            for (const j of 0..4) word[j] = w[4 * (i - 1) + j];
            if (i % nk == 0) {
                const first = word[0];
                word[0] = subByte(word[1]) ^ Rcon[i / nk];
                word[1] = subByte(word[2]);
                word[2] = subByte(word[3]);
                word[3] = subByte(first);
            } else if (nk > 6 && i % nk == 4) {
                for (const j of 0..4) word[j] = subByte(word[j]);
            }
            for (const j of 0..4) w[4 * i + j] = w[4 * (i - nk) + j] ^ word[j];
        }

        return Aes { roundKeys: w, rounds };
    }

    /**
     * Encrypts one 16-byte block.
     *
     * @param block - The plaintext block
     * @returns The ciphertext block
     *
     * @remarks
     * It runs the cipher of FIPS 197, section 5.1: the first round key,
     * then rounds of SubBytes, ShiftRows, MixColumns, and AddRoundKey, with no MixColumns in the last round.
     * The state is column by column, as FIPS 197 lays the input out.
     * The time is the same for every block and every key of a length.
     *
     * @example
     * ```hx
     * // the key 00 01 02 ... 0f and the block 00 11 22 ... ff of FIPS 197, appendix C.1
     * const aes = try Aes.init(&key);
     * aes.encryptBlock(block); // 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a
     * ```
     *
     * @since 1.0.0
     */

    encryptBlock(this: readonly *Aes, block: u8[16]): u8[16] {
        let state: u8[16] = undefined;
        for (const i of 0..16) state[i] = block[i] ^ this.roundKeys[i];
        for (const n of 1..this.rounds + 1) {
            // SubBytes and ShiftRows together: row r of column c comes from column c + r.
            let next: u8[16] = undefined;
            for (const column of 0..4) {
                for (const row of 0..4) next[row + 4 * column] = subByte(state[row + 4 * ((column + row) % 4)]);
            }
            if (n != this.rounds) mixColumns(&next);
            for (const i of 0..16) state[i] = next[i] ^ this.roundKeys[16 * n + i];
        }
        return state;
    }
}
