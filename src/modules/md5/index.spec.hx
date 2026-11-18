/**
 * Imports
 */

import { encodeHex } from "@hex";
import { md5 } from "@md5";

/**
 * Tests
 */

describe("md5") {
    test("should hash the empty message") {
        const digest = md5("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("d41d8cd98f00b204e9800998ecf8427e");
    }

    test("should hash the message abc") {
        const digest = md5("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("900150983cd24fb0d6963f7d28e17f72");
    }

    test("should hash the 448-bit NIST message") {
        const digest = md5("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("8215ef0796a20bcaaae116d3876c664a");
    }

    test("should hash the 896-bit NIST message") {
        const digest = md5("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("03dd8807a93175fb062dfb55dc7d359c");
    }

    test("should hash runs of a around the block boundary of 64 bytes") {
        let bytes: u8[65] = undefined;
        for (const i of 0..65) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest55 = md5(bytes[0..55]);
        const text55: string = try encodeHex(&digest55, &out);
        expect(text55).toBe("ef1772b6dff9a122358552954ad0df65");
        const digest56 = md5(bytes[0..56]);
        const text56: string = try encodeHex(&digest56, &out);
        expect(text56).toBe("3b0c8ac703f828b04c6c197006d17218");
        const digest63 = md5(bytes[0..63]);
        const text63: string = try encodeHex(&digest63, &out);
        expect(text63).toBe("b06521f39153d618550606be297466d5");
        const digest64 = md5(bytes[0..64]);
        const text64: string = try encodeHex(&digest64, &out);
        expect(text64).toBe("014842d480b571495a4a0363793f7367");
        const digest65 = md5(bytes[0..65]);
        const text65: string = try encodeHex(&digest65, &out);
        expect(text65).toBe("c743a45e0d2e6a95cb859adae0248435");
    }
}
