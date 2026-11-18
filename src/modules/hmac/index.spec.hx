/**
 * Imports
 */

import { encodeHex } from "@hex";
import { HmacSha256, hmacSha256, verifyHmacSha256 } from "@hmac";

/**
 * Tests
 */

describe("hmacSha256") {
    test("should match RFC 4231 test case 1") {
        let key: u8[20] = undefined;
        for (const _, i of key) key[i] = 0x0B;
        const tag = hmacSha256(&key, "Hi There");
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(&tag, &hex);
        expect(text).toBe("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    test("should match RFC 4231 test case 2") {
        const tag = hmacSha256("Jefe", "what do ya want for nothing?");
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(&tag, &hex);
        expect(text).toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    test("should hash a key longer than the block, as in RFC 4231 test case 6") {
        let key: u8[131] = undefined;
        for (const _, i of key) key[i] = 0xAA;
        const tag = hmacSha256(&key, "Test Using Larger Than Block-Size Key - Hash Key First");
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(&tag, &hex);
        expect(text).toBe("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    test("should use a key of exactly one block as it is") {
        let key: u8[64] = undefined;
        for (const _, i of key) key[i] = 0xAA;
        const tag = hmacSha256(&key, "x");
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(&tag, &hex);
        expect(text).toBe("ce3c639dcb9d8baae5d44c3b8b5e233faab4d1860e07489af5c84f213998bd79");
    }

    test("should accept an empty key and message") {
        const tag = hmacSha256("", "");
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(&tag, &hex);
        expect(text).toBe("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    }
}

describe("HmacSha256") {
    test("should give the same MAC wherever the message is split") {
        const message = "what do ya want for nothing?";
        for (const i of 0..message.len + 1) {
            let mac = HmacSha256.init("Jefe");
            mac.update(message[0..i]);
            mac.update(message[i..message.len]);
            const tag = mac.finish();
            let hex: u8[64] = undefined;
            const text: string = try encodeHex(&tag, &hex);
            expect(text).toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        }
    }

    test("should keep the state when finishing") {
        let mac = HmacSha256.init("Jefe");
        mac.update("what do ya want ");
        void mac.finish();
        mac.update("for nothing?");
        const tag = mac.finish();
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(&tag, &hex);
        expect(text).toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }
}

describe("verifyHmacSha256") {
    test("should accept the right tag") {
        const tag = hmacSha256("Jefe", "what do ya want for nothing?");
        expect(verifyHmacSha256("Jefe", "what do ya want for nothing?", &tag)).toBeTrue();
    }

    test("should reject a changed message, a wrong key, or a changed tag") {
        let tag = hmacSha256("Jefe", "what do ya want for nothing?");
        expect(verifyHmacSha256("Jefe", "what do ya want for nothing!", &tag)).toBeFalse();
        expect(verifyHmacSha256("jefe", "what do ya want for nothing?", &tag)).toBeFalse();
        tag[31] ^= 1;
        expect(verifyHmacSha256("Jefe", "what do ya want for nothing?", &tag)).toBeFalse();
    }

    test("should reject a truncated tag") {
        const tag = hmacSha256("Jefe", "what do ya want for nothing?");
        expect(verifyHmacSha256("Jefe", "what do ya want for nothing?", tag[0..16])).toBeFalse();
    }
}
