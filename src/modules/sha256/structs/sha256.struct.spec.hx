/**
 * Imports
 */

import { encodeHex } from "@hex";
import { Sha224, Sha256 } from "@sha256/structs/sha256.struct";

/**
 * Tests
 */

describe("Sha256") {
    test("should finish to the digest of no bytes") {
        const hash = Sha256.init();
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    test("should give the same digest wherever the 448-bit message is split") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Sha256.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            const digest = hash.finish();
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha256.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    }

    test("should keep the state when finishing") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Sha256.init();
        hash.update(message[0..32]);
        const early = hash.finish();
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("b09cbd263b043f000c5befcaa40bc2f55a4785e024e5deb749b56061eafb65e9");
        hash.update(message[32..message.len]);
        const digest = hash.finish();
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Sha256.init();
        for (const _ of 0..1000) hash.update(&chunk);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    test("should count the bytes and keep a partial block waiting") {
        let hash = Sha256.init();
        expect(hash.state[0]).toBe(0x6a09e667);
        hash.update("abc");
        expect(hash.length).toBe(3);
        expect(hash.used).toBe(3);
        expect(hash.block[0]).toBe('a');
    }
}

describe("Sha224") {
    test("should finish to the digest of no bytes") {
        const hash = Sha224.init();
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

    test("should give the same digest wherever the 448-bit message is split") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Sha224.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            const digest = hash.finish();
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha224.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3");
    }

    test("should keep the state when finishing") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Sha224.init();
        hash.update(message[0..32]);
        const early = hash.finish();
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("d7d147b9b2bc45479a494087ef8d212ef37910aa52462cce9c4dc8b7");
        hash.update(message[32..message.len]);
        const digest = hash.finish();
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Sha224.init();
        for (const _ of 0..1000) hash.update(&chunk);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67");
    }
}
