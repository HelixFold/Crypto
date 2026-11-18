/**
 * Imports
 */

import { crc32, crc64 } from "./hash";

/**
 * Tests
 */

describe("crc32") {
    test("should match the standard check value") {
        expect(crc32(0, "123456789")).toBe(0xCBF4_3926);
    }

    test("should continue across calls") {
        expect(crc32(crc32(0, "1234"), "56789")).toBe(0xCBF4_3926);
    }

    test("should leave the CRC of nothing at 0") {
        expect(crc32(0, "")).toBe(0);
    }
}

describe("crc64") {
    test("should match the standard check value") {
        expect(crc64(0, "123456789")).toBe(0x995D_C9BB_DF19_39FA);
    }

    test("should continue across calls") {
        expect(crc64(crc64(0, "12345"), "6789")).toBe(0x995D_C9BB_DF19_39FA);
    }
}
