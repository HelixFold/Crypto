/**
 * The first 32-bit prime of xxHash32.
 *
 * @remarks
 * xxHash32 multiplies by it after each rotation, and it seeds the first lane together with {@link Prime32B}.
 *
 * @since 1.0.0
 */

const Prime32A: u32 = 0x9E37_79B1;

/**
 * The second 32-bit prime of xxHash32.
 *
 * @remarks
 * Each input word is multiplied by it before it joins a lane, and the final mix uses it once.
 *
 * @since 1.0.0
 */

const Prime32B: u32 = 0x85EB_CA77;

/**
 * The third 32-bit prime of xxHash32.
 *
 * @remarks
 * Each word of the tail is multiplied by it, and the final mix uses it once.
 *
 * @since 1.0.0
 */

const Prime32C: u32 = 0xC2B2_AE3D;

/**
 * The fourth 32-bit prime of xxHash32.
 *
 * @remarks
 * Each word of the tail is multiplied by it after the rotation.
 *
 * @since 1.0.0
 */

const Prime32D: u32 = 0x27D4_EB2F;

/**
 * The fifth 32-bit prime of xxHash32.
 *
 * @remarks
 * It starts the hash of an input under 16 bytes, and each single byte of the tail is multiplied by it.
 *
 * @since 1.0.0
 */

const Prime32E: u32 = 0x1656_67B1;

/**
 * The negation of {@link Prime32A} modulo 2^32, which seeds the fourth lane of xxHash32.
 *
 * @remarks
 * The reference subtracts the prime from the seed.
 * Adding this constant with wrapping gives the same result without a wrapping subtraction.
 *
 * @since 1.0.0
 */

const MinusPrime32A: u32 = 0x61C8_864F;

/**
 * The first 64-bit prime of xxHash64.
 *
 * @remarks
 * Each round multiplies by it after its rotation, and it seeds the first lane together with {@link Prime64B}.
 *
 * @since 1.0.0
 */

const Prime64A: u64 = 0x9E37_79B1_85EB_CA87;

/**
 * The second 64-bit prime of xxHash64.
 *
 * @remarks
 * Each round multiplies its input by it, and the final mix uses it once.
 *
 * @since 1.0.0
 */

const Prime64B: u64 = 0xC2B2_AE3D_27D4_EB4F;

/**
 * The third 64-bit prime of xxHash64.
 *
 * @remarks
 * It is added after a 4-byte word of the tail, and the final mix uses it once.
 *
 * @since 1.0.0
 */

const Prime64C: u64 = 0x1656_67B1_9E37_79F9;

/**
 * The fourth 64-bit prime of xxHash64.
 *
 * @remarks
 * It is added after each lane merges and after each 8-byte word of the tail.
 *
 * @since 1.0.0
 */

const Prime64D: u64 = 0x85EB_CA77_C2B2_AE63;

/**
 * The fifth 64-bit prime of xxHash64.
 *
 * @remarks
 * It starts the hash of an input under 32 bytes, and each single byte of the tail is multiplied by it.
 *
 * @since 1.0.0
 */

const Prime64E: u64 = 0x27D4_EB2F_1656_67C5;

/**
 * The negation of {@link Prime64A} modulo 2^64, which seeds the fourth lane of xxHash64.
 *
 * @remarks
 * The reference subtracts the prime from the seed.
 * Adding this constant with wrapping gives the same result without a wrapping subtraction.
 *
 * @since 1.0.0
 */

const MinusPrime64A: u64 = 0x61C8_864E_7A14_3579;

/**
 * Rotates a 32-bit word left.
 *
 * @param x - The word
 * @param n - How many bits to rotate by, from 1 to 31
 * @returns The rotated word
 *
 * @remarks
 * Helix has no rotate operator, so it joins the two shifted halves.
 * A shift by 32 would trap, so `n` must not be 0.
 *
 * @since 1.0.0
 */

function rotl32(x: u32, n: u32): u32 {
    return (x << n) | (x >> (32 - n));
}

/**
 * Rotates a 64-bit word left.
 *
 * @param x - The word
 * @param n - How many bits to rotate by, from 1 to 63
 * @returns The rotated word
 *
 * @remarks
 * Helix has no rotate operator, so it joins the two shifted halves.
 * A shift by 64 would trap, so `n` must not be 0.
 *
 * @since 1.0.0
 */

function rotl64(x: u64, n: u64): u64 {
    return (x << n) | (x >> (64 - n));
}

/**
 * Reads a little-endian 32-bit word.
 *
 * @param bytes - The bytes
 * @param at - The index of the lowest byte
 * @returns The word
 *
 * @remarks
 * xxHash reads its input little-endian on every target, so the hash does not depend on the byte order.
 *
 * @since 1.0.0
 */

function read32(bytes: readonly u8[], at: usize): u32 {
    const low = (bytes[at] as u32) | ((bytes[at + 1] as u32) << 8);
    const high = (bytes[at + 2] as u32) | ((bytes[at + 3] as u32) << 8);

    return low | (high << 16);
}

/**
 * Reads a little-endian 64-bit word.
 *
 * @param bytes - The bytes
 * @param at - The index of the lowest byte
 * @returns The word
 *
 * @remarks
 * It joins two 32-bit reads, the lower address giving the low half.
 *
 * @since 1.0.0
 */

function read64(bytes: readonly u8[], at: usize): u64 {
    return (read32(bytes, at) as u64) | ((read32(bytes, at + 4) as u64) << 32);
}

/**
 * Runs one xxHash32 round, which folds a word of input into a lane.
 *
 * @param lane - The lane
 * @param word - The input word
 * @returns The new lane
 *
 * @remarks
 * It multiplies, adds, rotates by 13, and multiplies again, all with wrapping.
 *
 * @since 1.0.0
 */

function round32(lane: u32, word: u32): u32 {
    return rotl32(lane +% (word *% Prime32B), 13) *% Prime32A;
}

/**
 * Runs one xxHash64 round, which folds a word of input into a lane.
 *
 * @param lane - The lane, or 0 when the round only scrambles a word
 * @param word - The input word
 * @returns The new lane
 *
 * @remarks
 * It multiplies, adds, rotates by 31, and multiplies again, all with wrapping.
 * The merge of the lanes and the 8-byte tail both reuse it with a lane of 0.
 *
 * @since 1.0.0
 */

function round64(lane: u64, word: u64): u64 {
    return rotl64(lane +% (word *% Prime64B), 31) *% Prime64A;
}

/**
 * Folds one finished lane into the xxHash64 accumulator.
 *
 * @param hash - The accumulator
 * @param lane - The lane
 * @returns The new accumulator
 *
 * @remarks
 * Only inputs of 32 bytes or more have lanes, so only they run this step.
 *
 * @since 1.0.0
 */

function merge64(hash: u64, lane: u64): u64 {
    return ((hash ^ round64(0, lane)) *% Prime64A) +% Prime64D;
}

/**
 * Computes the 32-bit xxHash of bytes under a seed.
 *
 * @param bytes - The bytes
 * @param seed - A value that selects one hash function out of many, 0 by default in other tools
 * @returns Their hash, as the reference `XXH32` gives it
 *
 * @remarks
 * Inputs of 16 bytes or more run through four lanes of 4 bytes each,
 * and the tail then takes 4 bytes at a time and finally single bytes.
 * It is very fast on long inputs and passes the usual statistical tests,
 * which suits checksums of files, hash tables, and sharding.
 * It is not for security, since anyone can build inputs that collide even under a secret seed.
 *
 * @example
 * ```hx
 * xxHash32("", 0);    // 0x02CC5D05
 * xxHash32("abc", 0); // 0x32D153FF
 * ```
 *
 * @since 1.0.0
 */

export function xxHash32(bytes: readonly u8[], seed: u32): u32 {
    const length = bytes.len;
    let at: usize = 0;
    let hash: u32 = 0;
    if (length >= 16) {
        let lane1 = seed +% Prime32A +% Prime32B;
        let lane2 = seed +% Prime32B;
        let lane3 = seed;
        let lane4 = seed +% MinusPrime32A;
        while (length - at >= 16) {
            lane1 = round32(lane1, read32(bytes, at));
            lane2 = round32(lane2, read32(bytes, at + 4));
            lane3 = round32(lane3, read32(bytes, at + 8));
            lane4 = round32(lane4, read32(bytes, at + 12));
            at += 16;
        }
        hash = rotl32(lane1, 1) +% rotl32(lane2, 7) +% rotl32(lane3, 12) +% rotl32(lane4, 18);
    } else {
        hash = seed +% Prime32E;
    }
    hash +%= (length & 0xFFFF_FFFF) as u32;
    while (length - at >= 4) {
        hash = rotl32(hash +% (read32(bytes, at) *% Prime32C), 17) *% Prime32D;
        at += 4;
    }
    while (at < length) {
        hash = rotl32(hash +% ((bytes[at] as u32) *% Prime32E), 11) *% Prime32A;
        at += 1;
    }
    hash ^= hash >> 15;
    hash *%= Prime32B;
    hash ^= hash >> 13;
    hash *%= Prime32C;
    hash ^= hash >> 16;
    return hash;
}

/**
 * Computes the 64-bit xxHash of bytes under a seed.
 *
 * @param bytes - The bytes
 * @param seed - A value that selects one hash function out of many, 0 by default in other tools
 * @returns Their hash, as the reference `XXH64` gives it
 *
 * @remarks
 * Inputs of 32 bytes or more run through four lanes of 8 bytes each, which then merge into the hash,
 * and the tail then takes 8 bytes at a time, one 4-byte word, and finally single bytes.
 * It is faster than {@link xxHash32} on 64-bit targets, and its wider result makes accidental collisions rare.
 * It is not for security, since anyone can build inputs that collide even under a secret seed.
 *
 * @example
 * ```hx
 * xxHash64("", 0);    // 0xEF46DB3751D8E999
 * xxHash64("abc", 0); // 0x44BC2CF5AD770999
 * ```
 *
 * @since 1.0.0
 */

export function xxHash64(bytes: readonly u8[], seed: u64): u64 {
    const length = bytes.len;
    let at: usize = 0;
    let hash: u64 = 0;
    if (length >= 32) {
        let lane1 = seed +% Prime64A +% Prime64B;
        let lane2 = seed +% Prime64B;
        let lane3 = seed;
        let lane4 = seed +% MinusPrime64A;
        while (length - at >= 32) {
            lane1 = round64(lane1, read64(bytes, at));
            lane2 = round64(lane2, read64(bytes, at + 8));
            lane3 = round64(lane3, read64(bytes, at + 16));
            lane4 = round64(lane4, read64(bytes, at + 24));
            at += 32;
        }
        hash = rotl64(lane1, 1) +% rotl64(lane2, 7) +% rotl64(lane3, 12) +% rotl64(lane4, 18);
        hash = merge64(hash, lane1);
        hash = merge64(hash, lane2);
        hash = merge64(hash, lane3);
        hash = merge64(hash, lane4);
    } else {
        hash = seed +% Prime64E;
    }
    hash +%= length as u64;
    while (length - at >= 8) {
        hash = (rotl64(hash ^ round64(0, read64(bytes, at)), 27) *% Prime64A) +% Prime64D;
        at += 8;
    }
    if (length - at >= 4) {
        hash = (rotl64(hash ^ ((read32(bytes, at) as u64) *% Prime64A), 23) *% Prime64B) +% Prime64C;
        at += 4;
    }
    while (at < length) {
        hash = rotl64(hash ^ ((bytes[at] as u64) *% Prime64E), 11) *% Prime64A;
        at += 1;
    }
    hash ^= hash >> 33;
    hash *%= Prime64B;
    hash ^= hash >> 29;
    hash *%= Prime64C;
    hash ^= hash >> 32;
    return hash;
}
