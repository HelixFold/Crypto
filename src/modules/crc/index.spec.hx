/**
 * Imports
 */

import { crc32, crc32BZip2, crc64 } from "@crc";

/**
 * Tests
 */

describe("crc32") {
    test("should match the standard check value") {
        expect(crc32("123456789")).toBe(0xCBF4_3926);
    }

    test("should give zero for no bytes") {
        expect(crc32("")).toBe(0);
    }

    test("should match zlib on other inputs") {
        expect(crc32("a")).toBe(0xE8B7_BE43);
        expect(crc32("The quick brown fox jumps over the lazy dog")).toBe(0x414F_A339);
    }
}

describe("crc64") {
    test("should match the standard check value") {
        expect(crc64("123456789")).toBe(0x995D_C9BB_DF19_39FA);
    }

    test("should give zero for no bytes") {
        expect(crc64("")).toBe(0);
    }

    test("should match xz on other inputs") {
        expect(crc64("a")).toBe(0x3302_8477_2E65_2B05);
        expect(crc64("The quick brown fox jumps over the lazy dog")).toBe(0x5B5E_B8C2_E54A_A1C4);
    }
}

describe("crc32BZip2") {
    test("should match the standard check value") {
        expect(crc32BZip2("123456789")).toBe(0xFC89_1918);
    }

    test("should give zero for no bytes") {
        expect(crc32BZip2("")).toBe(0);
    }

    test("should match bzip2 on other inputs") {
        expect(crc32BZip2("a")).toBe(0x1993_9B6B);
        expect(crc32BZip2("The quick brown fox jumps over the lazy dog")).toBe(0x459D_EE61);
    }
}
