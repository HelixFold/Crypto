/**
 * Imports
 */

import { decodeHex, encodeHex } from "@hex";
import { X25519Error, x25519, x25519Base } from "@x25519";

/**
 * Tests
 */

describe("x25519") {
    test("should match the first RFC 7748 section 5.2 vector") {
        let scalar: u8[32] = undefined;
        let point: u8[32] = undefined;
        void try decodeHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", &scalar);
        void try decodeHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", &point);
        const shared = try x25519(&scalar, &point);
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&shared, &out);
        expect(text).toBe("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }

    test("should match the second RFC 7748 section 5.2 vector") {
        let scalar: u8[32] = undefined;
        let point: u8[32] = undefined;
        void try decodeHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", &scalar);
        void try decodeHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", &point);
        const shared = try x25519(&scalar, &point);
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&shared, &out);
        expect(text).toBe("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    }

    test("should ignore bit 255 of the point") {
        let scalar: u8[32] = undefined;
        let point: u8[32] = undefined;
        void try decodeHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", &scalar);
        void try decodeHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1ccc", &point);
        const shared = try x25519(&scalar, &point);
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&shared, &out);
        expect(text).toBe("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }

    test("should match the RFC 7748 iterated vectors after 1 and 1,000 iterations") {
        let k: u8[32] = undefined;
        for (const _, i of k) k[i] = 0;
        k[0] = 9;
        let u = k;
        let out: u8[64] = undefined;
        for (const n of 0..1000) {
            const next = try x25519(&k, &u);
            u = k;
            k = next;
            if (n == 0) {
                const first: string = try encodeHex(&k, &out);
                expect(first).toBe("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
            }
        }
        const text: string = try encodeHex(&k, &out);
        expect(text).toBe("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    }

    test("should give Alice and Bob the RFC 7748 section 6.1 shared secret") {
        let alicePrivate: u8[32] = undefined;
        let bobPrivate: u8[32] = undefined;
        void try decodeHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", &alicePrivate);
        void try decodeHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", &bobPrivate);
        const alicePublic = try x25519Base(&alicePrivate);
        const bobPublic = try x25519Base(&bobPrivate);
        let out: u8[64] = undefined;

        const aliceText: string = try encodeHex(&alicePublic, &out);
        expect(aliceText).toBe("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        const bobText: string = try encodeHex(&bobPublic, &out);
        expect(bobText).toBe("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        const aliceShared = try x25519(&alicePrivate, &bobPublic);
        const aliceSharedText: string = try encodeHex(&aliceShared, &out);
        expect(aliceSharedText).toBe("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        const bobShared = try x25519(&bobPrivate, &alicePublic);
        const bobSharedText: string = try encodeHex(&bobShared, &out);
        expect(bobSharedText).toBe("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    }

    test("should reject points of small order") {
        let scalar: u8[32] = undefined;
        for (const _, i of scalar) scalar[i] = i as u8;
        let point: u8[32] = undefined;

        void try decodeHex("0000000000000000000000000000000000000000000000000000000000000000", &point);
        expect(x25519(&scalar, &point)).toThrow(X25519Error.LowOrderPoint);
        void try decodeHex("0100000000000000000000000000000000000000000000000000000000000000", &point);
        expect(x25519(&scalar, &point)).toThrow(X25519Error.LowOrderPoint);
        void try decodeHex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", &point);
        expect(x25519(&scalar, &point)).toThrow(X25519Error.LowOrderPoint);
        void try decodeHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", &point);
        expect(x25519(&scalar, &point)).toThrow(X25519Error.LowOrderPoint);
    }

    test("should reject a scalar or a point that is not 32 bytes long") {
        let scalar: u8[32] = undefined;
        let point: u8[32] = undefined;
        for (const _, i of scalar) scalar[i] = 1;
        for (const _, i of point) point[i] = 0;
        point[0] = 9;
        expect(x25519(scalar[0..31], &point)).toThrow(X25519Error.BadKeyLength);
        expect(x25519(&scalar, point[0..31])).toThrow(X25519Error.BadKeyLength);
        expect(x25519("", "")).toThrow(X25519Error.BadKeyLength);
    }
}

describe("x25519Base") {
    test("should give the RFC 7748 section 6.1 public key of Bob") {
        let bobPrivate: u8[32] = undefined;
        void try decodeHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", &bobPrivate);
        const bobPublic = try x25519Base(&bobPrivate);
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&bobPublic, &out);
        expect(text).toBe("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    }

    test("should reject a scalar that is not 32 bytes long") {
        let scalar: u8[33] = undefined;
        for (const _, i of scalar) scalar[i] = 1;
        expect(x25519Base(&scalar)).toThrow(X25519Error.BadKeyLength);
    }
}
