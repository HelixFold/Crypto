/**
 * Imports
 */

import { encodeHex } from "@hex";
import { sha224, sha256 } from "@sha256";

/**
 * Tests
 */

describe("sha256") {
    test("should hash the empty message") {
        const digest = sha256("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    test("should hash the message abc") {
        const digest = sha256("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    test("should hash the 448-bit NIST message") {
        const digest = sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    test("should hash the 896-bit NIST message") {
        const digest = sha256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    }

    test("should hash runs of a around the block boundary of 64 bytes") {
        let bytes: u8[65] = undefined;
        for (const i of 0..65) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest55 = sha256(bytes[0..55]);
        const text55: string = try encodeHex(&digest55, &out);
        expect(text55).toBe("9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
        const digest56 = sha256(bytes[0..56]);
        const text56: string = try encodeHex(&digest56, &out);
        expect(text56).toBe("b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
        const digest63 = sha256(bytes[0..63]);
        const text63: string = try encodeHex(&digest63, &out);
        expect(text63).toBe("7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34");
        const digest64 = sha256(bytes[0..64]);
        const text64: string = try encodeHex(&digest64, &out);
        expect(text64).toBe("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
        const digest65 = sha256(bytes[0..65]);
        const text65: string = try encodeHex(&digest65, &out);
        expect(text65).toBe("635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0");
    }
}

describe("sha224") {
    test("should hash the empty message") {
        const digest = sha224("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

    test("should hash the message abc") {
        const digest = sha224("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    }

    test("should hash the 448-bit NIST message") {
        const digest = sha224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
    }

    test("should hash the 896-bit NIST message") {
        const digest = sha224("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3");
    }

    test("should hash runs of a around the block boundary of 64 bytes") {
        let bytes: u8[65] = undefined;
        for (const i of 0..65) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest55 = sha224(bytes[0..55]);
        const text55: string = try encodeHex(&digest55, &out);
        expect(text55).toBe("fb0bd626a70c28541dfa781bb5cc4d7d7f56622a58f01a0b1ddd646f");
        const digest56 = sha224(bytes[0..56]);
        const text56: string = try encodeHex(&digest56, &out);
        expect(text56).toBe("d40854fc9caf172067136f2e29e1380b14626bf6f0dd06779f820dcd");
        const digest63 = sha224(bytes[0..63]);
        const text63: string = try encodeHex(&digest63, &out);
        expect(text63).toBe("1d4e051f4d6fed2a63fd2421e65834cec00d64456553de3496ae8b1d");
        const digest64 = sha224(bytes[0..64]);
        const text64: string = try encodeHex(&digest64, &out);
        expect(text64).toBe("a88cd5cde6d6fe9136a4e58b49167461ea95d388ca2bdb7afdc3cbf4");
        const digest65 = sha224(bytes[0..65]);
        const text65: string = try encodeHex(&digest65, &out);
        expect(text65).toBe("ff8716f600af42959d0efb52e1f21b01bb328733009344d511c299fb");
    }
}
