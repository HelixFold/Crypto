/**
 * The 24 round constants of Keccak-f[1600], which the last step of each round adds to lane 0.
 *
 * @remarks
 * FIPS 202 derives them from a linear feedback shift register.
 * They break the symmetry between rounds, so no two rounds compute the same function.
 *
 * @example
 * ```hx
 * KeccakRoundConstants[1]; // 0x8082
 * ```
 *
 * @since 1.0.0
 */

export const KeccakRoundConstants: u64[24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/**
 * The left rotation of each lane in the combined rho and pi steps, in the order of {@link KeccakLanes}.
 *
 * @remarks
 * Entry `i` rotates the lane that moves into {@link KeccakLanes} entry `i`.
 * None is 0, so a rotation never shifts a lane by its full width.
 *
 * @example
 * ```hx
 * KeccakRotations[0]; // 1
 * ```
 *
 * @since 1.0.0
 */

export const KeccakRotations: u64[24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/**
 * The lanes that the combined rho and pi steps visit, in order, starting from lane 1.
 *
 * @remarks
 * Lane `x + 5 * y` holds the word at column `x` and row `y` of the state.
 * The walk carries each lane to the next position on the list, so one pass moves all 24 lanes besides lane 0.
 *
 * @example
 * ```hx
 * KeccakLanes[0]; // 10
 * ```
 *
 * @since 1.0.0
 */

export const KeccakLanes: usize[24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
