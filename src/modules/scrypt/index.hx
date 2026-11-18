/**
 * Exports
 */

export { ScryptError } from "@scrypt/errors/scrypt.error";

/**
 * Imports
 */

import { pbkdf2Sha256 } from "@pbkdf2";
import { alloc, Allocator, free } from "std/heap";
import { ScryptError } from "@scrypt/errors/scrypt.error";

/**
 * Rotates a 32-bit word left.
 *
 * @param x - The word
 * @param n - How many bits to rotate by, from 1 to 31
 * @returns The rotated word
 *
 * @remarks
 * Helix has no rotate operator, so it joins the two shifted halves.
 * Shifts drop the bits that leave the word, which is what makes the halves fit together.
 *
 * @since 1.0.0
 */

function rotl(x: u32, n: u32): u32 {
    return (x << n) | (x >> (32 - n));
}

/**
 * Runs one Salsa20 quarter-round on four words of the state.
 *
 * @param x - The 16-word state
 * @param a - The index of the first word, which takes the rotation by 18
 * @param b - The index of the second word, which takes the rotation by 7
 * @param c - The index of the third word, which takes the rotation by 9
 * @param d - The index of the fourth word, which takes the rotation by 13
 *
 * @remarks
 * The column rounds and the row rounds of Salsa20 are the same quarter-round on different indices,
 * so {@link salsa208} calls it eight times per double round.
 * It uses only wrapping additions, XORs, and rotations, so its timing never depends on the words.
 *
 * @since 1.0.0
 */

function quarterRound(x: u32[], a: usize, b: usize, c: usize, d: usize): void {
    x[b] ^= rotl(x[a] +% x[d], 7);
    x[c] ^= rotl(x[b] +% x[a], 9);
    x[d] ^= rotl(x[c] +% x[b], 13);
    x[a] ^= rotl(x[d] +% x[c], 18);
}

/**
 * Applies the Salsa20/8 core to a 64-byte block in place.
 *
 * @param block - The 16 little-endian words of the block
 *
 * @remarks
 * It runs four double rounds on a copy and then adds the copy back into the block, as RFC 7914 section 3 gives it.
 * Salsa20/8 is not a cipher here, only the mixing function inside {@link blockMix}.
 *
 * @since 1.0.0
 */

function salsa208(block: u32[]): void {
    let x: u32[16] = undefined;
    for (const i of 0..16) x[i] = block[i];
    for (const _ of 0..4) {
        quarterRound(&x, 0, 4, 8, 12);
        quarterRound(&x, 5, 9, 13, 1);
        quarterRound(&x, 10, 14, 2, 6);
        quarterRound(&x, 15, 3, 7, 11);
        quarterRound(&x, 0, 1, 2, 3);
        quarterRound(&x, 5, 6, 7, 4);
        quarterRound(&x, 10, 11, 8, 9);
        quarterRound(&x, 15, 12, 13, 14);
    }
    for (const i of 0..16) block[i] +%= x[i];
}

/**
 * Runs scryptBlockMix from one block of `32 * r` words into another.
 *
 * @param input - The block to mix, which stays as it is
 * @param output - The block for the result, which must not overlap `input`
 * @param r - The block size parameter
 *
 * @remarks
 * It chains Salsa20/8 over the `2 * r` 64-byte pieces of the input, starting from the last piece,
 * as RFC 7914 section 4 gives it.
 * It writes each result straight to its shuffled place, the even pieces to the first half and the odd ones to the
 * second half, so no separate shuffle pass is needed.
 *
 * @since 1.0.0
 */

function blockMix(input: readonly u32[], output: u32[], r: usize): void {
    let x: u32[16] = undefined;
    const last = (2 * r - 1) * 16;
    for (const k of 0..16) x[k] = input[last + k];
    for (const i of 0..2 * r) {
        for (const k of 0..16) x[k] ^= input[16 * i + k];
        salsa208(&x);
        const dest = (i / 2 + (i % 2) * r) * 16;
        for (const k of 0..16) output[dest + k] = x[k];
    }
}

/**
 * Reads the Integerify value of a block, the first 64 bits of its last 64-byte piece.
 *
 * @param x - The block of `32 * r` words
 * @param r - The block size parameter
 * @returns The value, which the caller reduces modulo `n`
 *
 * @remarks
 * RFC 7914 reads the whole last piece as a little-endian number,
 * but `n` is a power of two below 2^64, so the low 64 bits decide the result.
 *
 * @since 1.0.0
 */

function integerify(x: readonly u32[], r: usize): u64 {
    const at = (2 * r - 1) * 16;

    return (x[at] as u64) | ((x[at + 1] as u64) << 32);
}

/**
 * Reads a little-endian 32-bit word from four bytes.
 *
 * @param bytes - The bytes
 * @param at - The index of the lowest byte
 * @returns The word
 *
 * @remarks
 * scrypt stores every word little-endian, whatever the byte order of the target.
 *
 * @since 1.0.0
 */

function load32(bytes: readonly u8[], at: usize): u32 {
    const low = (bytes[at] as u32) | ((bytes[at + 1] as u32) << 8);
    const high = (bytes[at + 2] as u32) | ((bytes[at + 3] as u32) << 8);

    return low | (high << 16);
}

/**
 * Writes a 32-bit word as four little-endian bytes.
 *
 * @param bytes - The bytes
 * @param at - The index for the lowest byte
 * @param word - The word
 *
 * @remarks
 * It masks each byte before the cast, so the cast never has to truncate.
 *
 * @since 1.0.0
 */

function store32(bytes: u8[], at: usize, word: u32): void {
    bytes[at] = (word & 0xFF) as u8;
    bytes[at + 1] = ((word >> 8) & 0xFF) as u8;
    bytes[at + 2] = ((word >> 16) & 0xFF) as u8;
    bytes[at + 3] = ((word >> 24) & 0xFF) as u8;
}

/**
 * Runs scryptROMix on one block of `128 * r` bytes in place.
 *
 * @param block - The block, which holds the result afterward
 * @param v - Scratch space of `32 * r * n` words
 * @param xy - Scratch space of `64 * r` words
 * @param r - The block size parameter
 * @param n - The cost parameter, a power of two of at least 2
 *
 * @remarks
 * The first loop fills `v` with `n` successive mixes of the block,
 * and the second loop mixes in `n` entries of `v` that the running block chooses, as RFC 7914 section 5 gives it.
 * Both loops alternate between the two halves of `xy`, two steps per pass, so no block is ever copied back.
 * That relies on `n` being even, which every power of two from 2 up is.
 * The second loop reads `v` at an index derived from the password, which is how scrypt forces an attacker to keep
 * all of `v` in memory, and that access pattern is visible to a cache-timing attacker on the same machine.
 *
 * @since 1.0.0
 */

function roMix(block: u8[], v: u32[], xy: u32[], r: usize, n: usize): void {
    const words = 32 * r;
    const x = xy[0..words];
    const y = xy[words..2 * words];
    for (const k of 0..words) x[k] = load32(block, 4 * k);
    for (const i of 0..n / 2) {
        for (const k of 0..words) v[2 * i * words + k] = x[k];
        blockMix(x, y, r);
        for (const k of 0..words) v[(2 * i + 1) * words + k] = y[k];
        blockMix(y, x, r);
    }
    const mask = (n - 1) as u64;
    for (const _ of 0..n / 2) {
        const first = (integerify(x, r) & mask) as usize;
        for (const k of 0..words) x[k] ^= v[first * words + k];
        blockMix(x, y, r);
        const second = (integerify(y, r) & mask) as usize;
        for (const k of 0..words) y[k] ^= v[second * words + k];
        blockMix(y, x, r);
    }
    for (const k of 0..words) store32(block, 4 * k, x[k]);
}

/**
 * Derives key material from a password with scrypt, which costs both time and memory.
 *
 * @param allocator - The memory for the `128 * r * (n + p + 2)` bytes of working space
 * @param password - The password
 * @param salt - A random value unique to this password, 16 bytes or more
 * @param n - The cost, a power of two greater than 1 and below 2 to the power of `16 * r`
 * @param r - The block size, at least 1, usually 8
 * @param p - The parallelism, at least 1, with `p * r` below 2^30
 * @param out - The buffer for the derived key
 * @returns `out`, filled with the derived key
 * @throws ScryptError.BadCost when `n` is not a power of two greater than 1, or is too large for `r`
 * @throws ScryptError.BadBlockSize when `r` is 0
 * @throws ScryptError.BadParallelism when `p` is 0 or `p * r` reaches 2^30
 * @throws ScryptError.TooMuchMemory when the working space does not fit in a `usize`
 * @throws Pbkdf2Error.OutputTooLong when `out` is longer than PBKDF2 allows
 *
 * @remarks
 * It follows RFC 7914: PBKDF2-HMAC-SHA256 with one iteration stretches the password into `p` blocks,
 * scryptROMix mixes each block through `128 * r * n` bytes of memory,
 * and a second PBKDF2 with the blocks as the salt gives the output.
 * It checks every parameter before it allocates, and it frees all the working space before it returns.
 * The memory is the point, since it makes guessing expensive on custom hardware too,
 * so pick `n` as large as the system can afford with `r` of 8 and `p` of 1.
 * It has no branches on secret data, but the ROMix step reads memory at addresses derived from the password.
 * That is inherent to scrypt, so prefer it where no attacker shares the CPU cache with the process.
 *
 * @example
 * ```hx
 * let out: u8[64] = undefined;
 * try scrypt(allocator, "password", "NaCl", 1024, 8, 16, &out); // "fdbabe1c...a2cc0640", from RFC 7914
 * ```
 *
 * @see pbkdf2Sha256
 *
 * @since 1.0.0
 */

export function scrypt(
    allocator: dyn Allocator, password: readonly u8[], salt: readonly u8[], n: u64, r: u32, p: u32, out: u8[],
): u8[] | Error {
    if (n < 2 || (n & (n - 1)) != 0) throw ScryptError.BadCost;
    if (r == 0) throw ScryptError.BadBlockSize;
    if (p == 0) throw ScryptError.BadParallelism;
    const wideR = r as u64;
    if (16 * wideR < 64 && n >= (1 as u64) << (16 * wideR)) throw ScryptError.BadCost;
    if (wideR * (p as u64) >= (1 as u64) << 30) throw ScryptError.BadParallelism;
    const blockBytes = 128 * wideR;
    const limit = (~(0 as usize)) as u64;
    if (n > limit / blockBytes || (p as u64) > limit / blockBytes) throw ScryptError.TooMuchMemory;

    const rows = r as usize;
    const lanes = p as usize;
    const cost = n as usize;
    const blockLength = 128 * rows;
    const b = try alloc<u8>(allocator, blockLength * lanes);
    defer free(allocator, b);
    const xy = try alloc<u32>(allocator, 64 * rows);
    defer free(allocator, xy);
    const v = try alloc<u32>(allocator, 32 * rows * cost);
    defer free(allocator, v);

    void try pbkdf2Sha256(password, salt, 1, b);
    for (const i of 0..lanes) roMix(b[i * blockLength..(i + 1) * blockLength], v, xy, rows, cost);

    return try pbkdf2Sha256(password, b, 1, out);
}
