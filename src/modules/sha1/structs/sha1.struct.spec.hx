/**
 * Imports
 */

import { encodeHex } from "@hex";
import { Sha1 } from "@sha1/structs/sha1.struct";

/**
 * Tests
 */

describe("Sha1") {
    test("should finish to the digest of no bytes") {
        const hash = Sha1.init();
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    test("should give the same digest wherever the 448-bit message is split") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Sha1.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            const digest = hash.finish();
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha1.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("a49b2446a02c645bf419f995b67091253a04a259");
    }

    test("should keep the state when finishing") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Sha1.init();
        hash.update(message[0..32]);
        const early = hash.finish();
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("37bc5221ade3bc09cad15e4784f3c7051454b1b3");
        hash.update(message[32..message.len]);
        const digest = hash.finish();
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Sha1.init();
        for (const _ of 0..1000) hash.update(&chunk);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    test("should count the bytes and keep a partial block waiting") {
        let hash = Sha1.init();
        expect(hash.state[0]).toBe(0x67452301);
        hash.update("abc");
        expect(hash.length).toBe(3);
        expect(hash.used).toBe(3);
        expect(hash.block[0]).toBe('a');
    }
}
