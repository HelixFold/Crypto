/**
 * Imports
 */

import { decodeHex, encodeHex } from "@hex";
import { FieldOne, FieldZero } from "@curve25519";
import { Order } from "@ed25519/constants/ed25519.constant";
import {
    Point, packPoint, pointAdd, pointSwap, scalarMult, scalarMultBase, unpackNegative,
} from "@ed25519/components/point.component";

/**
 * Tests
 */

describe("packPoint") {
    test("should encode the neutral point as y = 1") {
        const neutral = Point { x: FieldZero, y: FieldOne, z: FieldOne, t: FieldZero };
        const packed = packPoint(neutral);
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&packed, &out);
        expect(text).toBe("0100000000000000000000000000000000000000000000000000000000000000");
    }
}

describe("scalarMultBase") {
    test("should give B for 1, 2 * B for 2, and the neutral point for 0 and L") {
        let scalar: u8[32] = undefined;
        for (const _, i of scalar) scalar[i] = 0;
        let out: u8[64] = undefined;

        const zero = packPoint(scalarMultBase(&scalar));
        const zeroText: string = try encodeHex(&zero, &out);
        expect(zeroText).toBe("0100000000000000000000000000000000000000000000000000000000000000");

        scalar[0] = 1;
        const one = packPoint(scalarMultBase(&scalar));
        const oneText: string = try encodeHex(&one, &out);
        expect(oneText).toBe("5866666666666666666666666666666666666666666666666666666666666666");

        scalar[0] = 2;
        const two = packPoint(scalarMultBase(&scalar));
        const twoText: string = try encodeHex(&two, &out);
        expect(twoText).toBe("c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022");

        const order = packPoint(scalarMultBase(&Order));
        const orderText: string = try encodeHex(&order, &out);
        expect(orderText).toBe("0100000000000000000000000000000000000000000000000000000000000000");
    }
}

describe("pointAdd") {
    test("should double B into 2 * B") {
        let scalar: u8[32] = undefined;
        for (const _, i of scalar) scalar[i] = 0;
        scalar[0] = 1;
        const b = scalarMultBase(&scalar);
        const doubled = packPoint(pointAdd(b, b));
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&doubled, &out);
        expect(text).toBe("c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022");
    }
}

describe("scalarMult") {
    test("should multiply an arbitrary point") {
        let scalar: u8[32] = undefined;
        for (const _, i of scalar) scalar[i] = 0;
        scalar[0] = 1;
        const b = scalarMultBase(&scalar);
        scalar[0] = 2;
        const doubled = packPoint(scalarMult(b, &scalar));
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&doubled, &out);
        expect(text).toBe("c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022");
    }
}

describe("pointSwap") {
    test("should swap for 1 and keep for 0") {
        let p = Point { x: FieldZero, y: FieldOne, z: FieldOne, t: FieldZero };
        let q = Point { x: FieldOne, y: FieldZero, z: FieldOne, t: FieldOne };
        pointSwap(&p, &q, 0);
        expect(p.x[0]).toBe(0);
        expect(q.x[0]).toBe(1);
        pointSwap(&p, &q, 1);
        expect(p.x[0]).toBe(1);
        expect(p.y[0]).toBe(0);
        expect(q.x[0]).toBe(0);
        expect(q.y[0]).toBe(1);
    }
}

describe("unpackNegative") {
    test("should decode B into -B") {
        let bytes: u8[32] = undefined;
        void try decodeHex("5866666666666666666666666666666666666666666666666666666666666666", &bytes);
        let decoded = false;
        if (const negative = unpackNegative(&bytes)) {
            decoded = true;
            const packed = packPoint(negative);
            let out: u8[64] = undefined;
            const text: string = try encodeHex(&packed, &out);
            expect(text).toBe("58666666666666666666666666666666666666666666666666666666666666e6");
        }
        expect(decoded).toBeTrue();
    }

    test("should reject a y with no point, a y of 2^255 - 19 or more, and x = 0 with the sign bit set") {
        let bytes: u8[32] = undefined;
        void try decodeHex("0200000000000000000000000000000000000000000000000000000000000000", &bytes);
        expect(unpackNegative(&bytes) == null).toBeTrue();
        void try decodeHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", &bytes);
        expect(unpackNegative(&bytes) == null).toBeTrue();
        void try decodeHex("0100000000000000000000000000000000000000000000000000000000000080", &bytes);
        expect(unpackNegative(&bytes) == null).toBeTrue();
    }
}
