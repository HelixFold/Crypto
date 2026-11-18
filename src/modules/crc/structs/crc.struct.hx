/**
 * Imports
 */

import { CRC32BZip2Table, CRC32Table, CRC64Table } from "@crc/constants/crc.constant";

/**
 * A running CRC-32 that takes its bytes in pieces.
 *
 * @remarks
 * It's the reflected CRC-32 of zlib, gzip, PNG, and xz, starting from all ones and inverted at the end.
 * Reach for it over {@link crc32} when the bytes arrive in chunks, as from a decoder or a stream.
 * Splitting the bytes at any point gives the same CRC as adding them at once.
 *
 * @example
 * ```hx
 * let check = CRC32.init();
 * check.update("1234");
 * check.update("56789");
 * check.finish(); // 0xCBF43926
 * ```
 *
 * @since 1.0.0
 */

export struct CRC32 {
    /**
     * The running value, inverted, as the table updates it.
     *
     * @remarks
     * It starts at `0xFFFFFFFF` and stays inverted until {@link CRC32.finish} flips it back.
     * Read the CRC through {@link CRC32.finish} rather than from this field.
     *
     * @example
     * ```hx
     * CRC32.init().state; // 0xFFFFFFFF
     * ```
     *
     * @since 1.0.0
     */

    state: u32,

    /**
     * Starts a CRC-32 of nothing yet.
     *
     * @returns The CRC
     *
     * @remarks
     * Finishing it before any update gives `0`, the CRC-32 of no bytes.
     *
     * @example
     * ```hx
     * CRC32.init().finish(); // 0
     * ```
     *
     * @since 1.0.0
     */

    init(): CRC32 {
        return CRC32 { state: 0xFFFF_FFFF };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * Each byte takes one table lookup, indexed by the low byte of the state, which then shifts right by 8.
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let check = CRC32.init();
     * check.update("123456789");
     * check.finish(); // 0xCBF43926
     * ```
     *
     * @since 1.0.0
     */

    update(this: *CRC32, bytes: readonly u8[]): void {
        let state = this.state;
        for (const byte of bytes) state = CRC32Table[((state ^ byte as u32) & 0xFF) as usize] ^ (state >> 8);
        this.state = state;
    }

    /**
     * Tells the CRC of every byte added so far.
     *
     * @returns The CRC
     *
     * @remarks
     * It leaves the state alone, so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let check = CRC32.init();
     * check.update("a");
     * check.finish(); // 0xE8B7BE43
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *CRC32): u32 {
        return this.state ^ 0xFFFF_FFFF;
    }
}

/**
 * A running CRC-64 that takes its bytes in pieces.
 *
 * @remarks
 * It's the reflected ECMA-182 CRC-64 that xz checks blocks with, starting from all ones and inverted at the end.
 * Reach for it over {@link crc64} when the bytes arrive in chunks, as from a decoder or a stream.
 * Splitting the bytes at any point gives the same CRC as adding them at once.
 *
 * @example
 * ```hx
 * let check = CRC64.init();
 * check.update("1234");
 * check.update("56789");
 * check.finish(); // 0x995DC9BBDF1939FA
 * ```
 *
 * @since 1.0.0
 */

export struct CRC64 {
    /**
     * The running value, inverted, as the table updates it.
     *
     * @remarks
     * It starts at `0xFFFFFFFFFFFFFFFF` and stays inverted until {@link CRC64.finish} flips it back.
     * Read the CRC through {@link CRC64.finish} rather than from this field.
     *
     * @example
     * ```hx
     * CRC64.init().state; // 0xFFFFFFFFFFFFFFFF
     * ```
     *
     * @since 1.0.0
     */

    state: u64,

    /**
     * Starts a CRC-64 of nothing yet.
     *
     * @returns The CRC
     *
     * @remarks
     * Finishing it before any update gives `0`, the CRC-64 of no bytes.
     *
     * @example
     * ```hx
     * CRC64.init().finish(); // 0
     * ```
     *
     * @since 1.0.0
     */

    init(): CRC64 {
        return CRC64 { state: 0xFFFF_FFFF_FFFF_FFFF };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * Each byte takes one table lookup, indexed by the low byte of the state, which then shifts right by 8.
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let check = CRC64.init();
     * check.update("123456789");
     * check.finish(); // 0x995DC9BBDF1939FA
     * ```
     *
     * @since 1.0.0
     */

    update(this: *CRC64, bytes: readonly u8[]): void {
        let state = this.state;
        for (const byte of bytes) state = CRC64Table[((state ^ byte as u64) & 0xFF) as usize] ^ (state >> 8);
        this.state = state;
    }

    /**
     * Tells the CRC of every byte added so far.
     *
     * @returns The CRC
     *
     * @remarks
     * It leaves the state alone, so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let check = CRC64.init();
     * check.update("a");
     * check.finish(); // 0x330284772E652B05
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *CRC64): u64 {
        return this.state ^ 0xFFFF_FFFF_FFFF_FFFF;
    }
}

/**
 * A running CRC-32 of bzip2 that takes its bytes in pieces.
 *
 * @remarks
 * It's the unreflected CRC-32 that bzip2 checks blocks with, also known as CRC-32/BZIP2.
 * It shares the polynomial of {@link CRC32} but feeds bits in from the top, so the two give different values.
 * It starts from all ones and is inverted at the end, like {@link CRC32}.
 * Combining the block CRCs into a stream CRC is up to the caller,
 * which rotates the stream value left by 1 and XORs in each block CRC.
 *
 * @example
 * ```hx
 * let check = CRC32BZip2.init();
 * check.update("1234");
 * check.update("56789");
 * check.finish(); // 0xFC891918
 * ```
 *
 * @since 1.0.0
 */

export struct CRC32BZip2 {
    /**
     * The running value, inverted, as the table updates it.
     *
     * @remarks
     * It starts at `0xFFFFFFFF` and stays inverted until {@link CRC32BZip2.finish} flips it back.
     * Read the CRC through {@link CRC32BZip2.finish} rather than from this field.
     *
     * @example
     * ```hx
     * CRC32BZip2.init().state; // 0xFFFFFFFF
     * ```
     *
     * @since 1.0.0
     */

    state: u32,

    /**
     * Starts a CRC-32 of bzip2 of nothing yet.
     *
     * @returns The CRC
     *
     * @remarks
     * Finishing it before any update gives `0`, the CRC of no bytes.
     *
     * @example
     * ```hx
     * CRC32BZip2.init().finish(); // 0
     * ```
     *
     * @since 1.0.0
     */

    init(): CRC32BZip2 {
        return CRC32BZip2 { state: 0xFFFF_FFFF };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * Each byte takes one table lookup, indexed by the high byte of the state, which then shifts left by 8.
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let check = CRC32BZip2.init();
     * check.update("123456789");
     * check.finish(); // 0xFC891918
     * ```
     *
     * @since 1.0.0
     */

    update(this: *CRC32BZip2, bytes: readonly u8[]): void {
        let state = this.state;
        for (const byte of bytes) {
            state = ((state << 8) & 0xFFFF_FFFF) ^ CRC32BZip2Table[(((state >> 24) ^ byte as u32) & 0xFF) as usize];
        }
        this.state = state;
    }

    /**
     * Tells the CRC of every byte added so far.
     *
     * @returns The CRC
     *
     * @remarks
     * It leaves the state alone, so more bytes may follow and a later call covers them too.
     * The result is the value that a bzip2 block header stores.
     *
     * @example
     * ```hx
     * let check = CRC32BZip2.init();
     * check.update("a");
     * check.finish(); // 0x19939B6B
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *CRC32BZip2): u32 {
        return this.state ^ 0xFFFF_FFFF;
    }
}
