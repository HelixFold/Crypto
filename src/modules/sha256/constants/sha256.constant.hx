/**
 * The 64 round constants of SHA-256 and SHA-224.
 *
 * @remarks
 * FIPS 180-4 defines them as the first 32 bits of the fractional parts of the cube roots of the first 64 primes.
 * Round `i` of the compression adds constant `i`.
 *
 * @example
 * ```hx
 * Sha256RoundConstants[0]; // 0x428A2F98
 * ```
 *
 * @since 1.0.0
 */

export const Sha256RoundConstants: u32[64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/**
 * The eight words that the state of every new SHA-256 starts from.
 *
 * @remarks
 * FIPS 180-4 defines them as the first 32 bits of the fractional parts of the square roots of the first 8 primes.
 *
 * @example
 * ```hx
 * Sha256InitialState[0]; // 0x6A09E667
 * ```
 *
 * @since 1.0.0
 */

export const Sha256InitialState: u32[8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/**
 * The eight words that the state of every new SHA-224 starts from.
 *
 * @remarks
 * FIPS 180-4 takes them from the square roots of the 9th through 16th primes,
 * so a SHA-224 never shares its state with a SHA-256 of the same bytes.
 *
 * @example
 * ```hx
 * Sha224InitialState[0]; // 0xC1059ED8
 * ```
 *
 * @since 1.0.0
 */

export const Sha224InitialState: u32[8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];
