/**
 * Imports
 */

import { decodeHex, encodeHex } from "@hex";
import {
    FieldOne, FieldZero, add, car25519, equal25519, inverse, mul, pack25519, parity25519, pow2523, sel25519, square,
    sub, unpack25519,
} from "@curve25519";

/**
 * Tests
 */

describe("unpack25519 and pack25519") {
    test("should round-trip a canonical value") {
        let bytes: u8[32] = undefined;
        void try decodeHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", &bytes);
        const packed = pack25519(unpack25519(&bytes));
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&packed, &out);
        expect(text).toBe("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    }

    test("should drop bit 255 on unpacking") {
        let bytes: u8[32] = undefined;
        void try decodeHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", &bytes);
        const packed = pack25519(unpack25519(&bytes));
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&packed, &out);
        expect(text).toBe("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e06b");
    }

    test("should reduce the modulus to zero") {
        let bytes: u8[32] = undefined;
        void try decodeHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", &bytes);
        const packed = pack25519(unpack25519(&bytes));
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&packed, &out);
        expect(text).toBe("0000000000000000000000000000000000000000000000000000000000000000");
    }

    test("should reduce 2^255 - 1 to 18") {
        let bytes: u8[32] = undefined;
        for (const _, i of bytes) bytes[i] = 0xFF;
        const packed = pack25519(unpack25519(&bytes));
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&packed, &out);
        expect(text).toBe("1200000000000000000000000000000000000000000000000000000000000000");
    }
}

describe("car25519") {
    test("should move the bits above 16 into the next limb") {
        let o = FieldZero;
        o[0] = 65541;
        car25519(&o);
        expect(o[0]).toBe(5);
        expect(o[1]).toBe(1);
        expect(o[2]).toBe(0);
    }

    test("should bring a negative limb into range without changing the value") {
        let o = FieldZero;
        o[0] = -1;
        car25519(&o);
        expect(o[0]).toBe(65497);
        for (const i of 1..16) expect(o[i]).toBe(65535);
        const packed = pack25519(o);
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&packed, &out);
        expect(text).toBe("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    }
}

describe("sel25519") {
    test("should leave both elements alone for a bit of 0") {
        let p = FieldZero;
        let q = FieldZero;
        p[0] = 1;
        p[1] = 2;
        q[0] = 4;
        q[1] = 5;
        sel25519(&p, &q, 0);
        expect(p[0]).toBe(1);
        expect(p[1]).toBe(2);
        expect(q[0]).toBe(4);
        expect(q[1]).toBe(5);
    }

    test("should swap both elements for a bit of 1") {
        let p = FieldZero;
        let q = FieldZero;
        p[0] = 1;
        p[1] = 2;
        q[0] = 4;
        q[1] = -5;
        sel25519(&p, &q, 1);
        expect(p[0]).toBe(4);
        expect(p[1]).toBe(-5);
        expect(q[0]).toBe(1);
        expect(q[1]).toBe(2);
    }
}

describe("field arithmetic") {
    test("should add, subtract, multiply, and square modulo 2^255 - 19") {
        let alice: u8[32] = undefined;
        let bob: u8[32] = undefined;
        void try decodeHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", &alice);
        void try decodeHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", &bob);
        const a = unpack25519(&alice);
        const b = unpack25519(&bob);
        let out: u8[64] = undefined;

        const sum = pack25519(add(a, b));
        const sumText: string = try encodeHex(&sum, &out);
        expect(sumText).toBe("e7b27588d5622fc9b5f740fed432752b4f88e0b011d94f28cea686cd1c420d16");

        const difference = pack25519(sub(a, b));
        const differenceText: string = try encodeHex(&difference, &out);
        expect(differenceText).toBe("075c648c10ce1a32c33441e7cd31585f6f117e5dc5a8e32c9448707e1e304c3e");

        const negative = pack25519(sub(b, a));
        const negativeText: string = try encodeHex(&negative, &out);
        expect(negativeText).toBe("e6a39b73ef31e5cd3ccbbe1832cea7a090ee81a23a571cd36bb78f81e1cfb341");

        const product = pack25519(mul(a, b));
        const productText: string = try encodeHex(&product, &out);
        expect(productText).toBe("382f741835ccbc7798acc885501d56395807ed723dae0afaa1bab7a3668bec1a");

        const squared = pack25519(square(a));
        const squaredText: string = try encodeHex(&squared, &out);
        expect(squaredText).toBe("f7d66ee37d3705a19d306103f387d709176a48bbadca0c1da9ef92c0cf7a6722");
    }

    test("should invert so that a times its inverse is one") {
        let alice: u8[32] = undefined;
        void try decodeHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", &alice);
        const a = unpack25519(&alice);
        expect(equal25519(mul(a, inverse(a)), FieldOne)).toBeTrue();

        const half = pack25519(inverse(add(FieldOne, FieldOne)));
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&half, &out);
        expect(text).toBe("f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f");
    }

    test("should raise to the power 2^252 - 3") {
        let alice: u8[32] = undefined;
        void try decodeHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", &alice);
        const power = pack25519(pow2523(unpack25519(&alice)));
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&power, &out);
        expect(text).toBe("3b6e6806deb02c7f3292c5d4f31680ed9c9c2409bdd7f50072a2e2be92096350");
    }
}

describe("equal25519 and parity25519") {
    test("should compare reduced values") {
        let modulus: u8[32] = undefined;
        void try decodeHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", &modulus);
        expect(equal25519(unpack25519(&modulus), FieldZero)).toBeTrue();
        expect(equal25519(FieldOne, FieldZero)).toBeFalse();
    }

    test("should give the low bit of the reduced value") {
        expect(parity25519(FieldOne)).toBe(1);
        expect(parity25519(FieldZero)).toBe(0);
        expect(parity25519(sub(FieldZero, FieldOne))).toBe(0);
    }
}
