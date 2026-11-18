/**
 * Imports
 */

import { HexError, decodeHex, encodeHex } from "@hex";

/**
 * Tests
 */

describe("encodeHex") {
    test("should write each byte as two lowercase digits") {
        let out: u8[6] = undefined;
        const text: string = try encodeHex("\x00\xff\x10", &out);
        expect(text).toBe("00ff10");
    }

    test("should write nothing for no bytes") {
        let out: u8[2] = undefined;
        const text: string = try encodeHex("", &out);
        expect(text).toBe("");
    }

    test("should return only the digits when the buffer is longer") {
        let out: u8[8] = undefined;
        const text: string = try encodeHex("ab", &out);
        expect(text).toBe("6162");
    }

    test("should reject a buffer that is too small") {
        let out: u8[3] = undefined;
        expect(encodeHex("ab", &out)).toThrow(HexError.ShortBuffer);
    }
}

describe("decodeHex") {
    test("should read digits in either case") {
        let bytes: u8[3] = undefined;
        let out: u8[6] = undefined;
        const text: string = try encodeHex(try decodeHex("00FF1a", &bytes), &out);
        expect(text).toBe("00ff1a");
    }

    test("should round-trip every byte value") {
        let all: u8[256] = undefined;
        for (const _, i of all) all[i] = i as u8;
        let digits: u8[512] = undefined;
        let back: u8[256] = undefined;
        const bytes = try decodeHex(try encodeHex(&all, &digits), &back);
        expect(bytes.len).toBe(256);
        for (const byte, i of bytes) expect(byte).toBe(i as u8);
    }

    test("should reject an odd number of digits") {
        let out: u8[4] = undefined;
        expect(decodeHex("abc", &out)).toThrow(HexError.OddLength);
    }

    test("should reject characters that aren't hex digits") {
        let out: u8[4] = undefined;
        expect(decodeHex("zz", &out)).toThrow(HexError.BadDigit);
        expect(decodeHex("0x10", &out)).toThrow(HexError.BadDigit);
        expect(decodeHex("a ", &out)).toThrow(HexError.BadDigit);
    }

    test("should reject a buffer that is too small") {
        let out: u8[1] = undefined;
        expect(decodeHex("0011", &out)).toThrow(HexError.ShortBuffer);
    }
}
