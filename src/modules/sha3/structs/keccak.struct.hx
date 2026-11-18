/**
 * Imports
 */

import { KeccakLanes, KeccakRotations, KeccakRoundConstants } from "@sha3/constants/sha3.constant";

/**
 * Rotates a 64-bit lane to the left.
 *
 * @param x - The lane
 * @param n - The number of bits, from 1 to 63
 * @returns The lane with its high `n` bits moved to the bottom
 *
 * @remarks
 * A count of 0 would shift `x` right by 64, so only the nonzero counts of the theta step
 * and of {@link KeccakRotations} may reach it.
 *
 * @since 1.0.0
 */

function rotl(x: u64, n: u64): u64 {
    return (x << n) | (x >> (64 - n));
}

/**
 * Applies the 24 rounds of Keccak-f[1600] to a state.
 *
 * @param state - The 25 lanes, where lane `x + 5 * y` sits at column `x` and row `y`
 *
 * @remarks
 * Each round runs the five steps of FIPS 202 in order: theta mixes every column into its neighbors,
 * rho and pi rotate the lanes and move them along {@link KeccakLanes},
 * chi mixes each row, and iota adds the round constant to lane 0.
 * Every index that it uses is fixed, so its memory accesses never depend on the data.
 *
 * @since 1.0.0
 */

function permute(state: *u64[25]): void {
    for (const r of 0..24) {
        let columns: u64[5] = undefined;
        for (const x of 0..5) {
            columns[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (const x of 0..5) {
            const d = columns[(x + 4) % 5] ^ rotl(columns[(x + 1) % 5], 1);
            for (const y of 0..5) state[y * 5 + x] = state[y * 5 + x] ^ d;
        }

        let carry = state[1];
        for (const i of 0..24) {
            const lane = KeccakLanes[i];
            const next = state[lane];
            state[lane] = rotl(carry, KeccakRotations[i]);
            carry = next;
        }

        for (const y of 0..5) {
            let row: u64[5] = undefined;
            for (const x of 0..5) row[x] = state[y * 5 + x];
            for (const x of 0..5) state[y * 5 + x] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5]);
        }

        state[0] = state[0] ^ KeccakRoundConstants[r];
    }
}

/**
 * XORs one byte into the state at a byte offset.
 *
 * @param state - The 25 lanes
 * @param at - The offset of the byte, from 0 to 199
 * @param byte - The byte
 *
 * @remarks
 * FIPS 202 reads the state as 200 bytes with each lane little-endian, so byte `at` is byte `at % 8` of lane `at / 8`.
 * Working a byte at a time keeps the sponge correct for any rate and any split of the input.
 *
 * @since 1.0.0
 */

function xorByte(state: *u64[25], at: usize, byte: u8): void {
    const lane = at >> 3;
    state[lane] = state[lane] ^ ((byte as u64) << (((at & 7) * 8) as u64));
}

/**
 * A Keccak sponge with a rate in bytes and a domain suffix, which every SHA-3 hash and SHAKE builds on.
 *
 * @remarks
 * It absorbs bytes into the first `rate` bytes of a 200-byte state, running Keccak-f[1600] each time that part fills.
 * {@link Keccak.pad} appends the suffix and the final bit, then the sponge only squeezes.
 * The structs of `@sha3` choose the rate and the suffix, so reach for this only to build another member of the family.
 * Absorbing after {@link Keccak.pad} gives a meaningless result, and the structs of `@sha3` never do it.
 *
 * @example
 * ```hx
 * let sponge = Keccak.init(136, 0x06); // the parameters of SHA3-256
 * sponge.absorb("abc");
 * sponge.pad();
 * let digest: u8[32] = undefined;
 * sponge.squeeze(&digest); // 3a985da7...11431532 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Keccak {
    /**
     * The 25 lanes of the state, where lane `x + 5 * y` sits at column `x` and row `y`.
     *
     * @remarks
     * It starts at zero, and both absorbing and squeezing touch only its first `rate` bytes directly.
     *
     * @example
     * ```hx
     * Keccak.init(136, 0x06).state[0]; // 0
     * ```
     *
     * @since 1.0.0
     */

    state: u64[25],

    /**
     * The number of bytes that each permutation absorbs or squeezes.
     *
     * @remarks
     * It's 200 minus twice the security level in bytes, so SHA3-256 and SHAKE256 use 136 and SHAKE128 uses 168.
     *
     * @example
     * ```hx
     * Keccak.init(168, 0x1F).rate; // 168
     * ```
     *
     * @since 1.0.0
     */

    rate: usize,

    /**
     * The offset of the next byte to absorb or squeeze, from 0 to `rate`.
     *
     * @remarks
     * While absorbing, it stays below `rate`, since a full rate permutes at once.
     * While squeezing, it reaches `rate` and the next read permutes first.
     *
     * @example
     * ```hx
     * let sponge = Keccak.init(136, 0x06);
     * sponge.absorb("abc");
     * sponge.used; // 3
     * ```
     *
     * @since 1.0.0
     */

    used: usize,

    /**
     * The domain bits that {@link Keccak.pad} appends, with the first bit of the padding already set.
     *
     * @remarks
     * FIPS 202 gives `0x06` to the SHA-3 hashes and `0x1F` to SHAKE,
     * so the two families never give the same output for the same input.
     *
     * @example
     * ```hx
     * Keccak.init(136, 0x06).suffix; // 0x06
     * ```
     *
     * @since 1.0.0
     */

    suffix: u8,

    /**
     * Starts an empty sponge.
     *
     * @param rate - The rate in bytes, from 1 to 199
     * @param suffix - The domain bits with the first padding bit, as FIPS 202 gives them
     * @returns The sponge
     *
     * @remarks
     * It doesn't check the rate, since only the structs of `@sha3` call it with their fixed values.
     *
     * @example
     * ```hx
     * Keccak.init(72, 0x06).rate; // 72, the rate of SHA3-512
     * ```
     *
     * @since 1.0.0
     */

    init(rate: usize, suffix: u8): Keccak {
        let state: u64[25] = undefined;
        for (const i of 0..25) state[i] = 0;

        return Keccak { state, rate, used: 0, suffix };
    }

    /**
     * Absorbs bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * It XORs each byte into the state and permutes whenever `rate` bytes have gone in.
     * Splitting the bytes at any point gives the same state as absorbing them at once.
     *
     * @example
     * ```hx
     * let sponge = Keccak.init(136, 0x06);
     * sponge.absorb(bytes[0..136]);
     * sponge.used; // 0, after one permutation
     * ```
     *
     * @since 1.0.0
     */

    absorb(this: *Keccak, bytes: readonly u8[]): void {
        for (const byte of bytes) {
            xorByte(&this.state, this.used, byte);
            this.used += 1;
            if (this.used == this.rate) {
                permute(&this.state);
                this.used = 0;
            }
        }
    }

    /**
     * Ends the input and turns the sponge to squeezing.
     *
     * @remarks
     * It XORs the suffix at the current offset and `0x80` into the last byte of the rate,
     * which is the pad10*1 rule of FIPS 202, then permutes.
     * When only one byte of the rate is left, both land on it.
     * Call it exactly once, after the last {@link Keccak.absorb}.
     *
     * @example
     * ```hx
     * let sponge = Keccak.init(168, 0x1F);
     * sponge.pad();
     * let out: u8[32] = undefined;
     * sponge.squeeze(&out); // 7f9c2ba4...fa66ef26 as hex, SHAKE128 of no bytes
     * ```
     *
     * @since 1.0.0
     */

    pad(this: *Keccak): void {
        xorByte(&this.state, this.used, this.suffix);
        xorByte(&this.state, this.rate - 1, 0x80);
        permute(&this.state);
        this.used = 0;
    }

    /**
     * Fills a buffer with the next output bytes.
     *
     * @param out - The buffer to fill
     *
     * @remarks
     * It reads the state from the current offset and permutes each time that a whole rate has been read,
     * so calling it again continues the same output stream.
     * Only call it after {@link Keccak.pad}.
     *
     * @example
     * ```hx
     * let sponge = Keccak.init(168, 0x1F);
     * sponge.pad();
     * let out: u8[200] = undefined;
     * sponge.squeeze(out[0..7]);
     * sponge.squeeze(out[7..200]); // the same 200 bytes as one call
     * ```
     *
     * @since 1.0.0
     */

    squeeze(this: *Keccak, out: u8[]): void {
        for (const i of 0..out.len) {
            if (this.used == this.rate) {
                permute(&this.state);
                this.used = 0;
            }
            out[i] = @truncate(u8, this.state[this.used >> 3] >> (((this.used & 7) * 8) as u64));
            this.used += 1;
        }
    }
}
