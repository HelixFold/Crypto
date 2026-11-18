/**
 * Imports
 */

import { decodeHex, encodeHex } from "@hex";
import { Order } from "@ed25519/constants/ed25519.constant";
import { isCanonicalScalar, modOrder, reduceScalar } from "@ed25519/components/scalar.component";

/**
 * Tests
 */

describe("modOrder") {
    test("should take L + 5 to 5") {
        let x: i64[64] = undefined;
        for (const _, i of x) x[i] = 0;
        for (const byte, i of Order) x[i] = byte as i64;
        x[0] += 5;
        const reduced = modOrder(&x);
        expect(reduced[0]).toBe(5);
        for (const i of 1..32) expect(reduced[i]).toBe(0);
    }
}

describe("reduceScalar") {
    test("should take zero and L to zero") {
        let bytes: u8[64] = undefined;
        for (const _, i of bytes) bytes[i] = 0;
        const zero = reduceScalar(&bytes);
        for (const byte of zero) expect(byte).toBe(0);
        for (const byte, i of Order) bytes[i] = byte;
        const order = reduceScalar(&bytes);
        for (const byte of order) expect(byte).toBe(0);
    }

    test("should reduce the largest 64-byte value") {
        let bytes: u8[64] = undefined;
        for (const _, i of bytes) bytes[i] = 0xFF;
        const reduced = reduceScalar(&bytes);
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&reduced, &out);
        expect(text).toBe("000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903");
    }
}

describe("isCanonicalScalar") {
    test("should accept values below L") {
        let s: u8[32] = undefined;
        for (const _, i of s) s[i] = 0;
        expect(isCanonicalScalar(&s)).toBeTrue();
        void try decodeHex("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", &s);
        expect(isCanonicalScalar(&s)).toBeTrue();
    }

    test("should reject L and values above it") {
        expect(isCanonicalScalar(&Order)).toBeFalse();
        let s: u8[32] = undefined;
        for (const _, i of s) s[i] = 0xFF;
        expect(isCanonicalScalar(&s)).toBeFalse();
        void try decodeHex("eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", &s);
        expect(isCanonicalScalar(&s)).toBeFalse();
    }
}
