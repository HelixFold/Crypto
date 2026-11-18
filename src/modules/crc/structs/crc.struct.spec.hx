/**
 * Imports
 */

import { CRC32, CRC32BZip2, CRC64 } from "@crc/structs/crc.struct";

/**
 * Tests
 */

describe("CRC32") {
    test("should start inverted and finish to zero") {
        const check = CRC32.init();
        expect(check.state).toBe(0xFFFF_FFFF);
        expect(check.finish()).toBe(0);
    }

    test("should match the standard check value") {
        let check = CRC32.init();
        check.update("123456789");
        expect(check.finish()).toBe(0xCBF4_3926);
    }

    test("should give the same CRC wherever the bytes are split") {
        const text = "123456789";
        for (const i of 0..10) {
            let check = CRC32.init();
            check.update(text[0..i]);
            check.update(text[i..9]);
            expect(check.finish()).toBe(0xCBF4_3926);
        }
    }

    test("should keep the state when finishing") {
        let check = CRC32.init();
        check.update("1234");
        void check.finish();
        check.update("56789");
        expect(check.finish()).toBe(0xCBF4_3926);
    }

    test("should leave the state alone on an empty update") {
        let check = CRC32.init();
        check.update("a");
        check.update("");
        expect(check.finish()).toBe(0xE8B7_BE43);
    }
}

describe("CRC64") {
    test("should start inverted and finish to zero") {
        const check = CRC64.init();
        expect(check.state).toBe(0xFFFF_FFFF_FFFF_FFFF);
        expect(check.finish()).toBe(0);
    }

    test("should match the standard check value") {
        let check = CRC64.init();
        check.update("123456789");
        expect(check.finish()).toBe(0x995D_C9BB_DF19_39FA);
    }

    test("should give the same CRC wherever the bytes are split") {
        const text = "123456789";
        for (const i of 0..10) {
            let check = CRC64.init();
            check.update(text[0..i]);
            check.update(text[i..9]);
            expect(check.finish()).toBe(0x995D_C9BB_DF19_39FA);
        }
    }

    test("should keep the state when finishing") {
        let check = CRC64.init();
        check.update("1234");
        void check.finish();
        check.update("56789");
        expect(check.finish()).toBe(0x995D_C9BB_DF19_39FA);
    }
}

describe("CRC32BZip2") {
    test("should start inverted and finish to zero") {
        const check = CRC32BZip2.init();
        expect(check.state).toBe(0xFFFF_FFFF);
        expect(check.finish()).toBe(0);
    }

    test("should match the standard check value") {
        let check = CRC32BZip2.init();
        check.update("123456789");
        expect(check.finish()).toBe(0xFC89_1918);
    }

    test("should give the same CRC wherever the bytes are split") {
        const text = "123456789";
        for (const i of 0..10) {
            let check = CRC32BZip2.init();
            check.update(text[0..i]);
            check.update(text[i..9]);
            expect(check.finish()).toBe(0xFC89_1918);
        }
    }

    test("should keep the state when finishing") {
        let check = CRC32BZip2.init();
        check.update("1234");
        void check.finish();
        check.update("56789");
        expect(check.finish()).toBe(0xFC89_1918);
    }

    test("should differ from the reflected CRC-32") {
        let bzip = CRC32BZip2.init();
        let zlib = CRC32.init();
        bzip.update("a");
        zlib.update("a");
        expect(bzip.finish() == zlib.finish()).toBeFalse();
    }
}
