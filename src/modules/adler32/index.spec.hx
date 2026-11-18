/**
 * Imports
 */

import { adler32 } from "@adler32";

/**
 * Tests
 */

describe("adler32") {
    test("should match the published value for Wikipedia") {
        expect(adler32("Wikipedia")).toBe(0x11E6_0398);
    }

    test("should give one for no bytes") {
        expect(adler32("")).toBe(1);
    }

    test("should match zlib on other inputs") {
        expect(adler32("a")).toBe(0x0062_0062);
        expect(adler32("abc")).toBe(0x024D_0127);
        expect(adler32("123456789")).toBe(0x091E_01DE);
        expect(adler32("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(0x8C13_150C);
    }
}
