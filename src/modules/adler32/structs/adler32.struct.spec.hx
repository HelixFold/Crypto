/**
 * Imports
 */

import { Adler32 } from "@adler32/structs/adler32.struct";

/**
 * Tests
 */

describe("Adler32") {
    test("should start with sums of one and zero") {
        const check = Adler32.init();
        expect(check.a).toBe(1);
        expect(check.b).toBe(0);
        expect(check.finish()).toBe(1);
    }

    test("should match the published value for Wikipedia") {
        let check = Adler32.init();
        check.update("Wikipedia");
        expect(check.finish()).toBe(0x11E6_0398);
    }

    test("should give the same checksum wherever the bytes are split") {
        const text = "Wikipedia";
        for (const i of 0..10) {
            let check = Adler32.init();
            check.update(text[0..i]);
            check.update(text[i..9]);
            expect(check.finish()).toBe(0x11E6_0398);
        }
    }

    test("should keep the sums when finishing") {
        let check = Adler32.init();
        check.update("Wiki");
        void check.finish();
        check.update("pedia");
        expect(check.finish()).toBe(0x11E6_0398);
    }

    test("should reduce the sums at the chunk boundary without overflow") {
        let bytes: u8[5553] = undefined;
        for (const _, i of bytes) bytes[i] = 0xFF;
        let exact = Adler32.init();
        exact.update(bytes[0..5552]);
        expect(exact.finish()).toBe(0xF18F_9B8C);
        let over = Adler32.init();
        over.update(&bytes);
        expect(over.finish()).toBe(0x8E29_9C8B);
    }

    test("should match zlib on a long run of 0xFF in uneven pieces") {
        let bytes: u8[100000] = undefined;
        for (const _, i of bytes) bytes[i] = 0xFF;
        let check = Adler32.init();
        check.update(bytes[0..7]);
        check.update(bytes[7..60000]);
        check.update(bytes[60000..100000]);
        expect(check.finish()).toBe(0x149A_302C);
    }

    test("should match zlib on every byte value repeated") {
        let bytes: u8[20000] = undefined;
        for (const _, i of bytes) bytes[i] = (i % 256) as u8;
        let check = Adler32.init();
        check.update(&bytes);
        expect(check.finish()).toBe(0xA9FA_DD2B);
    }
}
