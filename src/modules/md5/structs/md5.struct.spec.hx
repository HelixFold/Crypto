/**
 * Imports
 */

import { encodeHex } from "@hex";
import { Md5 } from "@md5/structs/md5.struct";

/**
 * Tests
 */

describe("Md5") {
    test("should finish to the digest of no bytes") {
        const hash = Md5.init();
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("d41d8cd98f00b204e9800998ecf8427e");
    }

    test("should give the same digest wherever the 448-bit message is split") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Md5.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            const digest = hash.finish();
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("8215ef0796a20bcaaae116d3876c664a");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Md5.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("03dd8807a93175fb062dfb55dc7d359c");
    }

    test("should keep the state when finishing") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Md5.init();
        hash.update(message[0..32]);
        const early = hash.finish();
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("8f52322928b91bf06561ea38ddf1752e");
        hash.update(message[32..message.len]);
        const digest = hash.finish();
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("8215ef0796a20bcaaae116d3876c664a");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Md5.init();
        for (const _ of 0..1000) hash.update(&chunk);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("7707d6ae4e027c70eea2a935c2296f21");
    }

    test("should count the bytes and keep a partial block waiting") {
        let hash = Md5.init();
        expect(hash.state[0]).toBe(0x67452301);
        hash.update("abc");
        expect(hash.length).toBe(3);
        expect(hash.used).toBe(3);
        expect(hash.block[0]).toBe('a');
    }
}
