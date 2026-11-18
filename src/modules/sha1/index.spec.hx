/**
 * Imports
 */

import { encodeHex } from "@hex";
import { sha1 } from "@sha1";

/**
 * Tests
 */

describe("sha1") {
    test("should hash the empty message") {
        const digest = sha1("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    test("should hash the message abc") {
        const digest = sha1("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    test("should hash the 448-bit NIST message") {
        const digest = sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }

    test("should hash the 896-bit NIST message") {
        const digest = sha1("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("a49b2446a02c645bf419f995b67091253a04a259");
    }

    test("should hash runs of a around the block boundary of 64 bytes") {
        let bytes: u8[65] = undefined;
        for (const i of 0..65) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest55 = sha1(bytes[0..55]);
        const text55: string = try encodeHex(&digest55, &out);
        expect(text55).toBe("c1c8bbdc22796e28c0e15163d20899b65621d65a");
        const digest56 = sha1(bytes[0..56]);
        const text56: string = try encodeHex(&digest56, &out);
        expect(text56).toBe("c2db330f6083854c99d4b5bfb6e8f29f201be699");
        const digest63 = sha1(bytes[0..63]);
        const text63: string = try encodeHex(&digest63, &out);
        expect(text63).toBe("03f09f5b158a7a8cdad920bddc29b81c18a551f5");
        const digest64 = sha1(bytes[0..64]);
        const text64: string = try encodeHex(&digest64, &out);
        expect(text64).toBe("0098ba824b5c16427bd7a1122a5a442a25ec644d");
        const digest65 = sha1(bytes[0..65]);
        const text65: string = try encodeHex(&digest65, &out);
        expect(text65).toBe("11655326c708d70319be2610e8a57d9a5b959d3b");
    }
}
