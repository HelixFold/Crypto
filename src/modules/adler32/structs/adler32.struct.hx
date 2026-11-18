/**
 * The modulus of both Adler-32 sums, the largest prime below 2^16.
 *
 * @remarks
 * Both sums stay below it after every reduction, so each fits in 16 bits of the result.
 *
 * @since 1.0.0
 */

const Modulus: u32 = 65521;

/**
 * The most bytes that the sums can take before they must be reduced, as zlib's `NMAX` defines it.
 *
 * @remarks
 * After this many bytes of `0xFF` from sums just below {@link Modulus},
 * the second sum is still below 2^32, so the reduction can wait that long without overflow.
 * One more byte could overflow it.
 *
 * @since 1.0.0
 */

const ChunkLength: usize = 5552;

/**
 * A running Adler-32 that takes its bytes in pieces.
 *
 * @remarks
 * It's the checksum that zlib streams end with, as RFC 1950 defines it.
 * Reach for it over {@link adler32} when the bytes arrive in chunks, as from a decoder or a stream.
 * Splitting the bytes at any point gives the same checksum as adding them at once.
 * Adler-32 is not for security, since anyone can change the bytes and fix the checksum to match.
 * It is also weak on short inputs, where CRC-32 catches more errors.
 *
 * @example
 * ```hx
 * let check = Adler32.init();
 * check.update("Wiki");
 * check.update("pedia");
 * check.finish(); // 0x11E60398
 * ```
 *
 * @since 1.0.0
 */

export struct Adler32 {
    /**
     * The first sum, one plus every byte so far, modulo 65521.
     *
     * @remarks
     * It starts at `1`, and it forms the low 16 bits of the checksum.
     * Read the checksum through {@link Adler32.finish} rather than from this field.
     *
     * @example
     * ```hx
     * Adler32.init().a; // 1
     * ```
     *
     * @since 1.0.0
     */

    a: u32,

    /**
     * The second sum, the total of every value that the first sum has taken, modulo 65521.
     *
     * @remarks
     * It starts at `0`, and it forms the high 16 bits of the checksum.
     * It depends on where each byte sits, which the first sum alone would miss.
     *
     * @example
     * ```hx
     * Adler32.init().b; // 0
     * ```
     *
     * @since 1.0.0
     */

    b: u32,

    /**
     * Starts an Adler-32 of nothing yet.
     *
     * @returns The checksum
     *
     * @remarks
     * Finishing it before any update gives `1`, the Adler-32 of no bytes.
     *
     * @example
     * ```hx
     * Adler32.init().finish(); // 1
     * ```
     *
     * @since 1.0.0
     */

    init(): Adler32 {
        return Adler32 { a: 1, b: 0 };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * It adds up to 5552 bytes before it reduces the sums, as zlib does,
     * so the slow modulo runs once per chunk instead of once per byte.
     * An empty slice leaves the sums as they were.
     *
     * @example
     * ```hx
     * let check = Adler32.init();
     * check.update("Wikipedia");
     * check.finish(); // 0x11E60398
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Adler32, bytes: readonly u8[]): void {
        let a = this.a;
        let b = this.b;
        let start: usize = 0;
        while (start < bytes.len) {
            const end = bytes.len - start < ChunkLength ? bytes.len : start + ChunkLength;
            for (const byte of bytes[start..end]) {
                a += byte as u32;
                b += a;
            }
            a %= Modulus;
            b %= Modulus;
            start = end;
        }
        this.a = a;
        this.b = b;
    }

    /**
     * Tells the checksum of every byte added so far.
     *
     * @returns The checksum, the second sum in the high 16 bits and the first in the low 16
     *
     * @remarks
     * It leaves the sums alone, so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let check = Adler32.init();
     * check.update("a");
     * check.finish(); // 0x00620062
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Adler32): u32 {
        return (this.b << 16) | this.a;
    }
}
