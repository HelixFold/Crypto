/**
 * Imports
 */

import { decodeHex, encodeHex } from "@hex";
import { Base64Error, decodeBase64, decodeBase64Url, encodeBase64, encodeBase64Url } from "@base64";

/**
 * Tests
 */

describe("encodeBase64") {
    test("should match the RFC 4648 test vectors") {
        let out: u8[8] = undefined;
        const empty: string = try encodeBase64("", &out);
        expect(empty).toBe("");
        const f: string = try encodeBase64("f", &out);
        expect(f).toBe("Zg==");
        const fo: string = try encodeBase64("fo", &out);
        expect(fo).toBe("Zm8=");
        const foo: string = try encodeBase64("foo", &out);
        expect(foo).toBe("Zm9v");
        const foob: string = try encodeBase64("foob", &out);
        expect(foob).toBe("Zm9vYg==");
        const fooba: string = try encodeBase64("fooba", &out);
        expect(fooba).toBe("Zm9vYmE=");
        const foobar: string = try encodeBase64("foobar", &out);
        expect(foobar).toBe("Zm9vYmFy");
    }

    test("should use every character of the alphabet") {
        let bytes: u8[48] = undefined;
        void try decodeHex("00108310518720928b30d38f41149351559761969b71d79f", bytes[0..24]);
        void try decodeHex("8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf", bytes[24..48]);
        let out: u8[64] = undefined;
        const text: string = try encodeBase64(&bytes, &out);
        expect(text).toBe("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    }

    test("should return only the text when the buffer is longer") {
        let out: u8[16] = undefined;
        const text: string = try encodeBase64("\xfb\xff", &out);
        expect(text).toBe("+/8=");
    }

    test("should reject a buffer that is too small") {
        let out: u8[7] = undefined;
        expect(encodeBase64("foob", &out)).toThrow(Base64Error.ShortBuffer);
    }
}

describe("decodeBase64") {
    test("should match the RFC 4648 test vectors") {
        let out: u8[6] = undefined;
        const empty: string = try decodeBase64("", &out);
        expect(empty).toBe("");
        const f: string = try decodeBase64("Zg==", &out);
        expect(f).toBe("f");
        const fo: string = try decodeBase64("Zm8=", &out);
        expect(fo).toBe("fo");
        const foo: string = try decodeBase64("Zm9v", &out);
        expect(foo).toBe("foo");
        const foob: string = try decodeBase64("Zm9vYg==", &out);
        expect(foob).toBe("foob");
        const fooba: string = try decodeBase64("Zm9vYmE=", &out);
        expect(fooba).toBe("fooba");
        const foobar: string = try decodeBase64("Zm9vYmFy", &out);
        expect(foobar).toBe("foobar");
    }

    test("should round-trip every byte value") {
        let all: u8[256] = undefined;
        for (const _, i of all) all[i] = i as u8;
        let text: u8[344] = undefined;
        let back: u8[256] = undefined;
        const bytes = try decodeBase64(try encodeBase64(&all, &text), &back);
        expect(bytes.len).toBe(256);
        for (const byte, i of bytes) expect(byte).toBe(i as u8);
    }

    test("should read the standard characters for 62 and 63") {
        let out: u8[3] = undefined;
        let hex: u8[6] = undefined;
        const text: string = try encodeHex(try decodeBase64("+/+/", &out), &hex);
        expect(text).toBe("fbffbf");
    }

    test("should reject a length that is not a multiple of four") {
        let out: u8[8] = undefined;
        expect(decodeBase64("Zg", &out)).toThrow(Base64Error.BadLength);
        expect(decodeBase64("Zg=", &out)).toThrow(Base64Error.BadLength);
        expect(decodeBase64("Zm9vY", &out)).toThrow(Base64Error.BadLength);
    }

    test("should reject padding in the wrong place") {
        let out: u8[8] = undefined;
        expect(decodeBase64("Z===", &out)).toThrow(Base64Error.BadPadding);
        expect(decodeBase64("====", &out)).toThrow(Base64Error.BadPadding);
        expect(decodeBase64("Zg==Zm9v", &out)).toThrow(Base64Error.BadPadding);
        expect(decodeBase64("Zm=v", &out)).toThrow(Base64Error.BadPadding);
    }

    test("should reject characters outside the alphabet") {
        let out: u8[8] = undefined;
        expect(decodeBase64("Zm 9", &out)).toThrow(Base64Error.BadCharacter);
        expect(decodeBase64("Zm9v\nZg=", &out)).toThrow(Base64Error.BadCharacter);
        expect(decodeBase64("-_8=", &out)).toThrow(Base64Error.BadCharacter);
        expect(decodeBase64("Zm9\x80", &out)).toThrow(Base64Error.BadCharacter);
        expect(decodeBase64("Zm9:", &out)).toThrow(Base64Error.BadCharacter);
        expect(decodeBase64("Zm9@", &out)).toThrow(Base64Error.BadCharacter);
        expect(decodeBase64("Zm9[", &out)).toThrow(Base64Error.BadCharacter);
        expect(decodeBase64("Zm9{", &out)).toThrow(Base64Error.BadCharacter);
        expect(decodeBase64("Zm9`", &out)).toThrow(Base64Error.BadCharacter);
        expect(decodeBase64("Zm9,", &out)).toThrow(Base64Error.BadCharacter);
    }

    test("should reject unused bits that are not zero") {
        let out: u8[8] = undefined;
        expect(decodeBase64("Zh==", &out)).toThrow(Base64Error.TrailingBits);
        expect(decodeBase64("Zm9=", &out)).toThrow(Base64Error.TrailingBits);
    }

    test("should reject a buffer that is too small") {
        let out: u8[3] = undefined;
        expect(decodeBase64("Zm9vYg==", &out)).toThrow(Base64Error.ShortBuffer);
    }
}

describe("encodeBase64Url") {
    test("should write no padding") {
        let out: u8[8] = undefined;
        const f: string = try encodeBase64Url("f", &out);
        expect(f).toBe("Zg");
        const fo: string = try encodeBase64Url("fo", &out);
        expect(fo).toBe("Zm8");
        const foobar: string = try encodeBase64Url("foobar", &out);
        expect(foobar).toBe("Zm9vYmFy");
    }

    test("should use - and _ for 62 and 63") {
        let out: u8[4] = undefined;
        const text: string = try encodeBase64Url("\xfb\xff\xbf", &out);
        expect(text).toBe("-_-_");
    }

    test("should reject a buffer that is too small") {
        let out: u8[2] = undefined;
        expect(encodeBase64Url("fo", &out)).toThrow(Base64Error.ShortBuffer);
    }
}

describe("decodeBase64Url") {
    test("should read text without padding") {
        let out: u8[6] = undefined;
        const f: string = try decodeBase64Url("Zg", &out);
        expect(f).toBe("f");
        const fo: string = try decodeBase64Url("Zm8", &out);
        expect(fo).toBe("fo");
        const foobar: string = try decodeBase64Url("Zm9vYmFy", &out);
        expect(foobar).toBe("foobar");
    }

    test("should round-trip every byte value") {
        let all: u8[256] = undefined;
        for (const _, i of all) all[i] = i as u8;
        let text: u8[342] = undefined;
        let back: u8[256] = undefined;
        const encoded = try encodeBase64Url(&all, &text);
        expect(encoded.len).toBe(342);
        const bytes = try decodeBase64Url(encoded, &back);
        expect(bytes.len).toBe(256);
        for (const byte, i of bytes) expect(byte).toBe(i as u8);
    }

    test("should reject a single character left over") {
        let out: u8[8] = undefined;
        expect(decodeBase64Url("Z", &out)).toThrow(Base64Error.BadLength);
        expect(decodeBase64Url("Zm9vY", &out)).toThrow(Base64Error.BadLength);
    }

    test("should reject padding") {
        let out: u8[8] = undefined;
        expect(decodeBase64Url("Zg==", &out)).toThrow(Base64Error.BadPadding);
        expect(decodeBase64Url("Zm8=", &out)).toThrow(Base64Error.BadPadding);
    }

    test("should reject the standard characters") {
        let out: u8[8] = undefined;
        expect(decodeBase64Url("+/8", &out)).toThrow(Base64Error.BadCharacter);
    }

    test("should reject unused bits that are not zero") {
        let out: u8[8] = undefined;
        expect(decodeBase64Url("Zh", &out)).toThrow(Base64Error.TrailingBits);
        expect(decodeBase64Url("Zm9", &out)).toThrow(Base64Error.TrailingBits);
    }
}
