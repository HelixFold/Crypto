/**
 * Imports
 */

import { Keccak } from "@sha3/structs/keccak.struct";

/**
 * A running SHA3-224 that takes its bytes in pieces.
 *
 * @remarks
 * It's the SHA3-224 of FIPS 202, a Keccak sponge with a rate of 144 bytes that gives 28 bytes.
 * It shares nothing with SHA-2, so it stays sound if a flaw ever turns up in SHA-224.
 * Reach for it over {@link sha3x224} when the bytes arrive in chunks.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 *
 * @example
 * ```hx
 * let hash = Sha3x224.init();
 * hash.update("a");
 * hash.update("bc");
 * hash.finish(); // e642824c...73b46fdf as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Sha3x224 {
    /**
     * The sponge that absorbs the bytes.
     *
     * @remarks
     * {@link Sha3x224.finish} pads and squeezes a copy, so the sponge keeps absorbing afterwards.
     *
     * @example
     * ```hx
     * Sha3x224.init().sponge.rate; // 144
     * ```
     *
     * @since 1.0.0
     */

    sponge: Keccak,

    /**
     * Starts a SHA3-224 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the digest of no bytes.
     *
     * @example
     * ```hx
     * Sha3x224.init().finish(); // 6b4e0342...5b5a6bc7 as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Sha3x224 {
        return Sha3x224 { sponge: Keccak.init(144, 0x06) };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = Sha3x224.init();
     * hash.update("abc");
     * hash.finish(); // e642824c...73b46fdf as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Sha3x224, bytes: readonly u8[]): void {
        this.sponge.absorb(bytes);
    }

    /**
     * Tells the digest of every byte added so far.
     *
     * @returns The 28-byte digest
     *
     * @remarks
     * It pads and squeezes a copy of the sponge and leaves the state alone,
     * so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let hash = Sha3x224.init();
     * hash.update("a");
     * hash.finish(); // 9e86ff69...482b6a8b as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Sha3x224): u8[28] {
        let sponge = this.sponge;
        sponge.pad();
        let digest: u8[28] = undefined;
        sponge.squeeze(&digest);

        return digest;
    }
}

/**
 * A running SHA3-256 that takes its bytes in pieces.
 *
 * @remarks
 * It's the SHA3-256 of FIPS 202, a Keccak sponge with a rate of 136 bytes that gives 32 bytes.
 * It shares nothing with SHA-2, so it stays sound if a flaw ever turns up in SHA-256.
 * Reach for it over {@link sha3x256} when the bytes arrive in chunks.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 *
 * @example
 * ```hx
 * let hash = Sha3x256.init();
 * hash.update("a");
 * hash.update("bc");
 * hash.finish(); // 3a985da7...11431532 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Sha3x256 {
    /**
     * The sponge that absorbs the bytes.
     *
     * @remarks
     * {@link Sha3x256.finish} pads and squeezes a copy, so the sponge keeps absorbing afterwards.
     *
     * @example
     * ```hx
     * Sha3x256.init().sponge.rate; // 136
     * ```
     *
     * @since 1.0.0
     */

    sponge: Keccak,

    /**
     * Starts a SHA3-256 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the digest of no bytes.
     *
     * @example
     * ```hx
     * Sha3x256.init().finish(); // a7ffc6f8...80f8434a as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Sha3x256 {
        return Sha3x256 { sponge: Keccak.init(136, 0x06) };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = Sha3x256.init();
     * hash.update("abc");
     * hash.finish(); // 3a985da7...11431532 as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Sha3x256, bytes: readonly u8[]): void {
        this.sponge.absorb(bytes);
    }

    /**
     * Tells the digest of every byte added so far.
     *
     * @returns The 32-byte digest
     *
     * @remarks
     * It pads and squeezes a copy of the sponge and leaves the state alone,
     * so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let hash = Sha3x256.init();
     * hash.update("a");
     * hash.finish(); // 80084bf2...032ecd8b as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Sha3x256): u8[32] {
        let sponge = this.sponge;
        sponge.pad();
        let digest: u8[32] = undefined;
        sponge.squeeze(&digest);

        return digest;
    }
}

/**
 * A running SHA3-384 that takes its bytes in pieces.
 *
 * @remarks
 * It's the SHA3-384 of FIPS 202, a Keccak sponge with a rate of 104 bytes that gives 48 bytes.
 * It shares nothing with SHA-2, so it stays sound if a flaw ever turns up in SHA-384.
 * Reach for it over {@link sha3x384} when the bytes arrive in chunks.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 *
 * @example
 * ```hx
 * let hash = Sha3x384.init();
 * hash.update("a");
 * hash.update("bc");
 * hash.finish(); // ec014982...28376d25 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Sha3x384 {
    /**
     * The sponge that absorbs the bytes.
     *
     * @remarks
     * {@link Sha3x384.finish} pads and squeezes a copy, so the sponge keeps absorbing afterwards.
     *
     * @example
     * ```hx
     * Sha3x384.init().sponge.rate; // 104
     * ```
     *
     * @since 1.0.0
     */

    sponge: Keccak,

    /**
     * Starts a SHA3-384 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the digest of no bytes.
     *
     * @example
     * ```hx
     * Sha3x384.init().finish(); // 0c63a75b...58d5f004 as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Sha3x384 {
        return Sha3x384 { sponge: Keccak.init(104, 0x06) };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = Sha3x384.init();
     * hash.update("abc");
     * hash.finish(); // ec014982...28376d25 as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Sha3x384, bytes: readonly u8[]): void {
        this.sponge.absorb(bytes);
    }

    /**
     * Tells the digest of every byte added so far.
     *
     * @returns The 48-byte digest
     *
     * @remarks
     * It pads and squeezes a copy of the sponge and leaves the state alone,
     * so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let hash = Sha3x384.init();
     * hash.update("a");
     * hash.finish(); // 1815f774...12a4ccd9 as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Sha3x384): u8[48] {
        let sponge = this.sponge;
        sponge.pad();
        let digest: u8[48] = undefined;
        sponge.squeeze(&digest);

        return digest;
    }
}

/**
 * A running SHA3-512 that takes its bytes in pieces.
 *
 * @remarks
 * It's the SHA3-512 of FIPS 202, a Keccak sponge with a rate of 72 bytes that gives 64 bytes.
 * It shares nothing with SHA-2, so it stays sound if a flaw ever turns up in SHA-512.
 * Reach for it over {@link sha3x512} when the bytes arrive in chunks.
 * Splitting the bytes at any point gives the same digest as adding them at once.
 *
 * @example
 * ```hx
 * let hash = Sha3x512.init();
 * hash.update("a");
 * hash.update("bc");
 * hash.finish(); // b751850b...4eec53f0 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Sha3x512 {
    /**
     * The sponge that absorbs the bytes.
     *
     * @remarks
     * {@link Sha3x512.finish} pads and squeezes a copy, so the sponge keeps absorbing afterwards.
     *
     * @example
     * ```hx
     * Sha3x512.init().sponge.rate; // 72
     * ```
     *
     * @since 1.0.0
     */

    sponge: Keccak,

    /**
     * Starts a SHA3-512 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the digest of no bytes.
     *
     * @example
     * ```hx
     * Sha3x512.init().finish(); // a69f73cc...281dcd26 as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Sha3x512 {
        return Sha3x512 { sponge: Keccak.init(72, 0x06) };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = Sha3x512.init();
     * hash.update("abc");
     * hash.finish(); // b751850b...4eec53f0 as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Sha3x512, bytes: readonly u8[]): void {
        this.sponge.absorb(bytes);
    }

    /**
     * Tells the digest of every byte added so far.
     *
     * @returns The 64-byte digest
     *
     * @remarks
     * It pads and squeezes a copy of the sponge and leaves the state alone,
     * so more bytes may follow and a later call covers them too.
     *
     * @example
     * ```hx
     * let hash = Sha3x512.init();
     * hash.update("a");
     * hash.finish(); // 697f2d85...d09ab02a as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Sha3x512): u8[64] {
        let sponge = this.sponge;
        sponge.pad();
        let digest: u8[64] = undefined;
        sponge.squeeze(&digest);

        return digest;
    }
}

/**
 * The output side of a finished SHAKE, which squeezes as many bytes as the caller asks for.
 *
 * @remarks
 * {@link Shake128.finish} and {@link Shake256.finish} return it.
 * The output is one endless stream, so squeezing 10 bytes and then 22 gives the same 32 bytes as one call for 32.
 * The first bytes of a longer output equal a shorter output of the same input,
 * so derive keys of different lengths from different inputs.
 *
 * @example
 * ```hx
 * let hash = Shake128.init();
 * hash.update("abc");
 * let reader = hash.finish();
 * let out: u8[32] = undefined;
 * reader.squeeze(out[0..10]);
 * reader.squeeze(out[10..32]); // 5881092d...940f2cc8 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct ShakeReader {
    /**
     * The padded sponge that the output comes from.
     *
     * @remarks
     * Its offset marks how much of the stream {@link ShakeReader.squeeze} has already given.
     *
     * @example
     * ```hx
     * Shake128.init().finish().sponge.used; // 0
     * ```
     *
     * @since 1.0.0
     */

    sponge: Keccak,

    /**
     * Fills a buffer with the next bytes of the output.
     *
     * @param out - The buffer to fill, of any length
     *
     * @remarks
     * Each call continues where the last one stopped, across any number of permutations.
     *
     * @example
     * ```hx
     * let reader = Shake256.init().finish();
     * let out: u8[32] = undefined;
     * reader.squeeze(&out); // 46b9dd2b...6ed5762f as hex
     * ```
     *
     * @since 1.0.0
     */

    squeeze(this: *ShakeReader, out: u8[]): void {
        this.sponge.squeeze(out);
    }
}

/**
 * A running SHAKE128 that takes its bytes in pieces and gives an output of any length.
 *
 * @remarks
 * It's the extendable-output function SHAKE128 of FIPS 202, a Keccak sponge with a rate of 168 bytes.
 * It gives 128 bits of security against collisions and preimages once the output is at least 32 bytes.
 * Reach for it over {@link shake128} when the bytes arrive in chunks,
 * or when the output is read in pieces through a {@link ShakeReader}.
 *
 * @example
 * ```hx
 * let hash = Shake128.init();
 * hash.update("abc");
 * let reader = hash.finish();
 * let out: u8[32] = undefined;
 * reader.squeeze(&out); // 5881092d...940f2cc8 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Shake128 {
    /**
     * The sponge that absorbs the bytes.
     *
     * @remarks
     * {@link Shake128.finish} pads a copy, so the sponge keeps absorbing afterwards.
     *
     * @example
     * ```hx
     * Shake128.init().sponge.rate; // 168
     * ```
     *
     * @since 1.0.0
     */

    sponge: Keccak,

    /**
     * Starts a SHAKE128 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the output of no bytes.
     *
     * @example
     * ```hx
     * let reader = Shake128.init().finish();
     * let out: u8[32] = undefined;
     * reader.squeeze(&out); // 7f9c2ba4...fa66ef26 as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Shake128 {
        return Shake128 { sponge: Keccak.init(168, 0x1F) };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = Shake128.init();
     * hash.update("abc");
     * let reader = hash.finish();
     * let out: u8[32] = undefined;
     * reader.squeeze(&out); // 5881092d...940f2cc8 as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Shake128, bytes: readonly u8[]): void {
        this.sponge.absorb(bytes);
    }

    /**
     * Ends the input of a copy and returns a reader for its output.
     *
     * @returns The reader, positioned at the first output byte
     *
     * @remarks
     * It pads a copy of the sponge and leaves the state alone,
     * so more bytes may follow and a later call gives the output of them all.
     *
     * @example
     * ```hx
     * let hash = Shake128.init();
     * hash.update("abc");
     * let reader = hash.finish();
     * let out: u8[32] = undefined;
     * reader.squeeze(&out); // 5881092d...940f2cc8 as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Shake128): ShakeReader {
        let sponge = this.sponge;
        sponge.pad();

        return ShakeReader { sponge };
    }
}

/**
 * A running SHAKE256 that takes its bytes in pieces and gives an output of any length.
 *
 * @remarks
 * It's the extendable-output function SHAKE256 of FIPS 202, a Keccak sponge with a rate of 136 bytes.
 * It gives 256 bits of security against collisions and preimages once the output is at least 64 bytes.
 * Reach for it over {@link shake256} when the bytes arrive in chunks,
 * or when the output is read in pieces through a {@link ShakeReader}.
 *
 * @example
 * ```hx
 * let hash = Shake256.init();
 * hash.update("abc");
 * let reader = hash.finish();
 * let out: u8[32] = undefined;
 * reader.squeeze(&out); // 48336660...e78b5739 as hex
 * ```
 *
 * @since 1.0.0
 */

export struct Shake256 {
    /**
     * The sponge that absorbs the bytes.
     *
     * @remarks
     * {@link Shake256.finish} pads a copy, so the sponge keeps absorbing afterwards.
     *
     * @example
     * ```hx
     * Shake256.init().sponge.rate; // 136
     * ```
     *
     * @since 1.0.0
     */

    sponge: Keccak,

    /**
     * Starts a SHAKE256 of nothing yet.
     *
     * @returns The hash
     *
     * @remarks
     * Finishing it before any update gives the output of no bytes.
     *
     * @example
     * ```hx
     * let reader = Shake256.init().finish();
     * let out: u8[32] = undefined;
     * reader.squeeze(&out); // 46b9dd2b...6ed5762f as hex
     * ```
     *
     * @since 1.0.0
     */

    init(): Shake256 {
        return Shake256 { sponge: Keccak.init(136, 0x1F) };
    }

    /**
     * Adds bytes.
     *
     * @param bytes - The bytes
     *
     * @remarks
     * An empty slice leaves the state as it was.
     *
     * @example
     * ```hx
     * let hash = Shake256.init();
     * hash.update("abc");
     * let reader = hash.finish();
     * let out: u8[32] = undefined;
     * reader.squeeze(&out); // 48336660...e78b5739 as hex
     * ```
     *
     * @since 1.0.0
     */

    update(this: *Shake256, bytes: readonly u8[]): void {
        this.sponge.absorb(bytes);
    }

    /**
     * Ends the input of a copy and returns a reader for its output.
     *
     * @returns The reader, positioned at the first output byte
     *
     * @remarks
     * It pads a copy of the sponge and leaves the state alone,
     * so more bytes may follow and a later call gives the output of them all.
     *
     * @example
     * ```hx
     * let hash = Shake256.init();
     * hash.update("abc");
     * let reader = hash.finish();
     * let out: u8[32] = undefined;
     * reader.squeeze(&out); // 48336660...e78b5739 as hex
     * ```
     *
     * @since 1.0.0
     */

    finish(this: readonly *Shake256): ShakeReader {
        let sponge = this.sponge;
        sponge.pad();

        return ShakeReader { sponge };
    }
}
