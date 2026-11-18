/**
 * Imports
 */

import { encodeHex } from "@hex";
import { HkdfError, hkdfSha256, hkdfSha256Expand, hkdfSha256Extract } from "@hkdf";

/**
 * Tests
 */

describe("hkdfSha256Extract") {
    test("should match RFC 5869 test case 1") {
        let ikm: u8[22] = undefined;
        for (const _, i of ikm) ikm[i] = 0x0B;
        let salt: u8[13] = undefined;
        for (const _, i of salt) salt[i] = i as u8;
        const prk = hkdfSha256Extract(&salt, &ikm);
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(&prk, &hex);
        expect(text).toBe("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    }

    test("should match RFC 5869 test case 2") {
        let ikm: u8[80] = undefined;
        for (const _, i of ikm) ikm[i] = i as u8;
        let salt: u8[80] = undefined;
        for (const _, i of salt) salt[i] = (0x60 + i) as u8;
        const prk = hkdfSha256Extract(&salt, &ikm);
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(&prk, &hex);
        expect(text).toBe("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
    }

    test("should treat an empty salt as 32 zero bytes, as in RFC 5869 test case 3") {
        let ikm: u8[22] = undefined;
        for (const _, i of ikm) ikm[i] = 0x0B;
        let zeros: u8[32] = undefined;
        for (const _, i of zeros) zeros[i] = 0;
        const empty = hkdfSha256Extract("", &ikm);
        const padded = hkdfSha256Extract(&zeros, &ikm);
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(&empty, &hex);
        expect(text).toBe("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        const other: string = try encodeHex(&padded, &hex);
        expect(other).toBe("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    }
}

describe("hkdfSha256Expand") {
    test("should match RFC 5869 test case 1") {
        let ikm: u8[22] = undefined;
        for (const _, i of ikm) ikm[i] = 0x0B;
        let salt: u8[13] = undefined;
        for (const _, i of salt) salt[i] = i as u8;
        let info: u8[10] = undefined;
        for (const _, i of info) info[i] = (0xF0 + i) as u8;
        const prk = hkdfSha256Extract(&salt, &ikm);
        let out: u8[42] = undefined;
        let hex: u8[84] = undefined;
        const text: string = try encodeHex(try hkdfSha256Expand(&prk, &info, &out), &hex);
        expect(text).toBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    test("should give a prefix of the longer output for a shorter buffer") {
        const prk = hkdfSha256Extract("salt", "ikm");
        let out: u8[33] = undefined;
        let hex: u8[66] = undefined;
        const long: string = try encodeHex(try hkdfSha256Expand(&prk, "info", &out), &hex);
        expect(long).toBe("fe8f9615d2374c0d17f77d1aeaf408c2e75fe0466073d0def23c733e2f862dfd68");
        const short: string = try encodeHex(try hkdfSha256Expand(&prk, "info", out[0..32]), &hex);
        expect(short).toBe("fe8f9615d2374c0d17f77d1aeaf408c2e75fe0466073d0def23c733e2f862dfd");
    }

    test("should write nothing for an empty buffer") {
        const prk = hkdfSha256Extract("salt", "ikm");
        let out: u8[1] = undefined;
        expect((try hkdfSha256Expand(&prk, "info", out[0..0])).len).toBe(0);
    }

    test("should fill the largest output of 255 blocks") {
        const prk = hkdfSha256Extract("salt", "ikm");
        let out: u8[8160] = undefined;
        const okm = try hkdfSha256Expand(&prk, "info", &out);
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(okm[8128..8160], &hex);
        expect(text).toBe("f10be4d813d4647001096e6c6efca36a7ec49a08915e6f50d16fecad12b8e8b9");
    }

    test("should reject an output longer than 255 blocks") {
        const prk = hkdfSha256Extract("salt", "ikm");
        let out: u8[8161] = undefined;
        expect(hkdfSha256Expand(&prk, "info", &out)).toThrow(HkdfError.OutputTooLong);
    }
}

describe("hkdfSha256") {
    test("should match RFC 5869 test case 2") {
        let ikm: u8[80] = undefined;
        for (const _, i of ikm) ikm[i] = i as u8;
        let salt: u8[80] = undefined;
        for (const _, i of salt) salt[i] = (0x60 + i) as u8;
        let info: u8[80] = undefined;
        for (const _, i of info) info[i] = (0xB0 + i) as u8;
        let out: u8[82] = undefined;
        const okm = try hkdfSha256(&salt, &ikm, &info, &out);
        let hex: u8[82] = undefined;
        const head: string = try encodeHex(okm[0..41], &hex);
        expect(head).toBe("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271");
        const tail: string = try encodeHex(okm[41..82], &hex);
        expect(tail).toBe("cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
    }

    test("should match RFC 5869 test case 3, with no salt and no info") {
        let ikm: u8[22] = undefined;
        for (const _, i of ikm) ikm[i] = 0x0B;
        let out: u8[42] = undefined;
        let hex: u8[84] = undefined;
        const text: string = try encodeHex(try hkdfSha256("", &ikm, "", &out), &hex);
        expect(text).toBe("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    }

    test("should reject an output longer than 255 blocks") {
        let out: u8[8161] = undefined;
        expect(hkdfSha256("salt", "ikm", "info", &out)).toThrow(HkdfError.OutputTooLong);
    }
}
