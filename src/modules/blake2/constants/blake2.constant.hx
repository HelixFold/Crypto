/**
 * The eight words that the state of every BLAKE2b starts from, before the parameter block.
 *
 * @remarks
 * RFC 7693 reuses the initial state of SHA-512.
 * The compression also mixes these words into the second half of its working vector.
 *
 * @example
 * ```hx
 * Blake2bInitialState[0]; // 0x6A09E667F3BCC908
 * ```
 *
 * @since 1.0.0
 */

export const Blake2bInitialState: u64[8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/**
 * The eight words that the state of every BLAKE2s starts from, before the parameter block.
 *
 * @remarks
 * RFC 7693 reuses the initial state of SHA-256.
 * The compression also mixes these words into the second half of its working vector.
 *
 * @example
 * ```hx
 * Blake2sInitialState[0]; // 0x6A09E667
 * ```
 *
 * @since 1.0.0
 */

export const Blake2sInitialState: u32[8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/**
 * The order that each round of BLAKE2 reads the 16 message words in, 16 entries per round.
 *
 * @remarks
 * RFC 7693 lists ten permutations.
 * Round `r` reads the row at `r % 10` from offset `16 * (r % 10)`,
 * so BLAKE2b's rounds 10 and 11 reuse the first two rows.
 * The entries index message words and never depend on the key or the message.
 *
 * @example
 * ```hx
 * Blake2Sigma[16]; // 14
 * ```
 *
 * @since 1.0.0
 */

export const Blake2Sigma: usize[160] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
];
