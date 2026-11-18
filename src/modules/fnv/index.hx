/**
 * The starting value of FNV-1a with 32 bits, the FNV-0 hash of a fixed string.
 *
 * @remarks
 * It is also the hash of no bytes, since the loop never runs.
 *
 * @since 1.0.0
 */

const Offset32: u32 = 0x811C_9DC5;

/**
 * The 32-bit FNV prime, 2^24 + 2^8 + 0x93.
 *
 * @remarks
 * Its few set bits spread each byte across the word with one multiplication.
 *
 * @since 1.0.0
 */

const Prime32: u32 = 0x0100_0193;

/**
 * The starting value of FNV-1a with 64 bits, the FNV-0 hash of a fixed string.
 *
 * @remarks
 * It is also the hash of no bytes, since the loop never runs.
 *
 * @since 1.0.0
 */

const Offset64: u64 = 0xCBF2_9CE4_8422_2325;

/**
 * The 64-bit FNV prime, 2^40 + 2^8 + 0xB3.
 *
 * @remarks
 * Its few set bits spread each byte across the word with one multiplication.
 *
 * @since 1.0.0
 */

const Prime64: u64 = 0x0000_0100_0000_01B3;

/**
 * Computes the 32-bit FNV-1a hash of bytes.
 *
 * @param bytes - The bytes
 * @returns Their hash
 *
 * @remarks
 * Each byte is XORed into the hash, which is then multiplied by the FNV prime, wrapping at 32 bits.
 * It is short and fast on short keys, which suits hash tables and other in-memory lookups.
 * It is not for security, since anyone can find inputs that collide or that flood one bucket of a table.
 * Prefer {@link xxHash32} for long inputs, where it is much faster.
 *
 * @example
 * ```hx
 * fnv1a32("");       // 0x811C9DC5
 * fnv1a32("foobar"); // 0xBF9CF968
 * ```
 *
 * @since 1.0.0
 */

export function fnv1a32(bytes: readonly u8[]): u32 {
    let hash = Offset32;
    for (const byte of bytes) hash = (hash ^ byte as u32) *% Prime32;
    return hash;
}

/**
 * Computes the 64-bit FNV-1a hash of bytes.
 *
 * @param bytes - The bytes
 * @returns Their hash
 *
 * @remarks
 * Each byte is XORed into the hash, which is then multiplied by the FNV prime, wrapping at 64 bits.
 * Its wider result makes accidental collisions rare even across millions of keys.
 * It is not for security, since anyone can find inputs that collide or that flood one bucket of a table.
 * Prefer {@link xxHash64} for long inputs, where it is much faster.
 *
 * @example
 * ```hx
 * fnv1a64("");       // 0xCBF29CE484222325
 * fnv1a64("foobar"); // 0x85944171F73967E8
 * ```
 *
 * @since 1.0.0
 */

export function fnv1a64(bytes: readonly u8[]): u64 {
    let hash = Offset64;
    for (const byte of bytes) hash = (hash ^ byte as u64) *% Prime64;
    return hash;
}
