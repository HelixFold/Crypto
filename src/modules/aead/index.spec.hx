/**
 * Imports
 */

import { decodeHex, encodeHex } from "@hex";
import { AeadError, chacha20Poly1305Open, chacha20Poly1305Seal } from "@aead";

/**
 * Decodes rows of hex one after another into a buffer.
 *
 * @param rows - The rows of hex digits, in order
 * @param out - The buffer, at least as long as the decoded bytes
 * @returns The part of `out` that holds the decoded bytes
 *
 * @remarks
 * Each row holds up to 32 bytes, so a long vector stays within the line limit.
 *
 * @since 1.0.0
 */

function decodeRows(rows: readonly string[], out: u8[]): u8[] | Error {
    let at: usize = 0;
    for (const row of rows) {
        const bytes = try decodeHex(row, out[at..]);
        at += bytes.len;
    }
    return out[0..at];
}

/**
 * Picks one 32-byte row out of a byte string.
 *
 * @param bytes - The bytes
 * @param row - The index of the row
 * @returns The bytes of that row, shorter for the last row
 *
 * @remarks
 * It pairs with {@link decodeRows}, so the test compares output row by row against the same hex rows.
 *
 * @since 1.0.0
 */

function rowOf(bytes: readonly u8[], row: usize): readonly u8[] {
    const end = 32 * row + 32 < bytes.len ? 32 * row + 32 : bytes.len;
    return bytes[32 * row..end];
}

/**
 * Writes the plaintext of RFC 8439, section 2.8.2, into a buffer.
 *
 * @param out - The buffer, at least 114 bytes long
 * @returns The part of `out` that holds the 114 bytes of text
 *
 * @remarks
 * The text is longer than one line, so it's copied from two literals.
 *
 * @since 1.0.0
 */

function sunscreen(out: u8[]): u8[] {
    const first = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for ";
    const second = "the future, sunscreen would be it.";
    for (const byte, i of first) out[i] = byte;
    for (const byte, i of second) out[first.len + i] = byte;
    return out[0..first.len + second.len];
}

/**
 * Tests
 */

describe("chacha20Poly1305Seal") {
    test("should match the AEAD vector of RFC 8439, section 2.8.2") {
        let key: u8[32] = undefined;
        void try decodeHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", &key);
        let nonce: u8[12] = undefined;
        void try decodeHex("070000004041424344454647", &nonce);
        let aad: u8[12] = undefined;
        void try decodeHex("50515253c0c1c2c3c4c5c6c7", &aad);
        let text: u8[114] = undefined;
        const plain = sunscreen(&text);
        let out: u8[114] = undefined;
        const tag = try chacha20Poly1305Seal(&key, &nonce, &aad, plain, &out);

        let tagDigits: u8[32] = undefined;
        const tagText: string = try encodeHex(&tag, &tagDigits);
        expect(tagText).toBe("1ae10b594f09e26a7e902ecbd0600691");
        const rows: string[4] = [
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
        ];
        for (const row, i of rows) {
            let digits: u8[64] = undefined;
            const rowText: string = try encodeHex(rowOf(&out, i), &digits);
            expect(rowText).toBe(row);
        }
    }

    test("should seal an empty message with empty associated data") {
        let key: u8[32] = undefined;
        void try decodeHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", &key);
        let nonce: u8[12] = undefined;
        void try decodeHex("070000004041424344454647", &nonce);
        let out: u8[1] = undefined;
        const tag = try chacha20Poly1305Seal(&key, &nonce, "", "", &out);
        let digits: u8[32] = undefined;
        const text: string = try encodeHex(&tag, &digits);
        expect(text).toBe("a0784d7a4716f3feb4f64e7f4b39bf04");
    }

    test("should seal a message shorter than one block") {
        let key: u8[32] = undefined;
        void try decodeHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", &key);
        let nonce: u8[12] = undefined;
        void try decodeHex("070000004041424344454647", &nonce);
        let out: u8[3] = undefined;
        const tag = try chacha20Poly1305Seal(&key, &nonce, "", "abc", &out);
        let digits: u8[32] = undefined;
        const text: string = try encodeHex(&tag, &digits);
        expect(text).toBe("ee33b7c3cf0742d9c56155b194616080");
        let cipherDigits: u8[6] = undefined;
        const cipherText: string = try encodeHex(&out, &cipherDigits);
        expect(cipherText).toBe("fe198a");
    }

    test("should reject a key, a nonce, or a buffer of the wrong length") {
        let key: u8[33] = undefined;
        for (const _, i of key) key[i] = 0;
        let nonce: u8[13] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        let out: u8[3] = undefined;
        expect(chacha20Poly1305Seal(key[0..31], nonce[0..12], "", "abc", &out)).toThrow(AeadError.BadKeyLength);
        expect(chacha20Poly1305Seal(&key, nonce[0..12], "", "abc", &out)).toThrow(AeadError.BadKeyLength);
        expect(chacha20Poly1305Seal(key[0..32], &nonce, "", "abc", &out)).toThrow(AeadError.BadNonceLength);
        expect(chacha20Poly1305Seal(key[0..32], nonce[0..12], "", "abcd", &out)).toThrow(AeadError.ShortBuffer);
    }
}

describe("chacha20Poly1305Open") {
    test("should open the vector of RFC 8439, appendix A.5") {
        let key: u8[32] = undefined;
        void try decodeHex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", &key);
        let nonce: u8[12] = undefined;
        void try decodeHex("000000000102030405060708", &nonce);
        let aad: u8[12] = undefined;
        void try decodeHex("f33388860000000000004e91", &aad);
        let tag: u8[16] = undefined;
        void try decodeHex("eead9d67890cbb22392336fea1851f38", &tag);
        const cipherRows: string[9] = [
            "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2",
            "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf",
            "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855",
            "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4",
            "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e",
            "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a",
            "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10",
            "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29",
            "a6ad5cb4022b02709b",
        ];
        let buffer: u8[265] = undefined;
        const ciphertext = try decodeRows(&cipherRows, &buffer);
        let out: u8[265] = undefined;
        const plain = try chacha20Poly1305Open(&key, &nonce, &aad, ciphertext, &tag, &out);
        expect(plain.len).toBe(265);

        const plainRows: string[9] = [
            "496e7465726e65742d4472616674732061726520647261667420646f63756d65",
            "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d",
            "6f6e74687320616e64206d617920626520757064617465642c207265706c6163",
            "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65",
            "6e747320617420616e792074696d652e20497420697320696e617070726f7072",
            "6961746520746f2075736520496e7465726e65742d4472616674732061732072",
            "65666572656e6365206d6174657269616c206f7220746f206369746520746865",
            "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67",
            "726573732e2fe2809d",
        ];
        for (const row, i of plainRows) {
            let digits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(plain, i), &digits);
            expect(text).toBe(row);
        }
        const start: string = plain[0..15];
        expect(start).toBe("Internet-Drafts");
    }

    test("should give back what was sealed") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = i as u8;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 0x24;
        const message = "a message of seventy-two bytes, so it ends partway into its second block";
        let sealed: u8[72] = undefined;
        const tag = try chacha20Poly1305Seal(&key, &nonce, "header", message, &sealed);
        let opened: u8[72] = undefined;
        const plain = try chacha20Poly1305Open(&key, &nonce, "header", &sealed, &tag, &opened);
        const text: string = plain;
        expect(text).toBe(message);
    }

    test("should open in place") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = i as u8;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 1;
        let buffer: u8[5] = undefined;
        for (const byte, i of "hello") buffer[i] = byte;
        const tag = try chacha20Poly1305Seal(&key, &nonce, "", &buffer, &buffer);
        const plain = try chacha20Poly1305Open(&key, &nonce, "", &buffer, &tag, &buffer);
        const text: string = plain;
        expect(text).toBe("hello");
    }

    test("should open an empty message with empty associated data") {
        let key: u8[32] = undefined;
        void try decodeHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", &key);
        let nonce: u8[12] = undefined;
        void try decodeHex("070000004041424344454647", &nonce);
        let tag: u8[16] = undefined;
        void try decodeHex("a0784d7a4716f3feb4f64e7f4b39bf04", &tag);
        let out: u8[1] = undefined;
        const plain = try chacha20Poly1305Open(&key, &nonce, "", "", &tag, &out);
        expect(plain.len).toBe(0);
    }

    test("should reject a changed ciphertext, tag, or associated data, and release nothing") {
        let key: u8[32] = undefined;
        void try decodeHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", &key);
        let nonce: u8[12] = undefined;
        void try decodeHex("070000004041424344454647", &nonce);
        let aad: u8[12] = undefined;
        void try decodeHex("50515253c0c1c2c3c4c5c6c7", &aad);
        let text: u8[114] = undefined;
        const plain = sunscreen(&text);
        let sealed: u8[114] = undefined;
        let tag = try chacha20Poly1305Seal(&key, &nonce, &aad, plain, &sealed);
        let out: u8[114] = undefined;
        for (const _, i of out) out[i] = 0xAA;

        sealed[113] ^= 0x01;
        expect(chacha20Poly1305Open(&key, &nonce, &aad, &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        sealed[113] ^= 0x01;
        sealed[0] ^= 0x80;
        expect(chacha20Poly1305Open(&key, &nonce, &aad, &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        sealed[0] ^= 0x80;

        tag[15] ^= 0x01;
        expect(chacha20Poly1305Open(&key, &nonce, &aad, &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        tag[15] ^= 0x01;

        aad[0] ^= 0x01;
        expect(chacha20Poly1305Open(&key, &nonce, &aad, &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        aad[0] ^= 0x01;
        expect(chacha20Poly1305Open(&key, &nonce, aad[0..11], &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        expect(chacha20Poly1305Open(&key, &nonce, "", &sealed, &tag, &out)).toThrow(AeadError.BadTag);

        for (const byte of out) expect(byte).toBe(0xAA);

        const opened = try chacha20Poly1305Open(&key, &nonce, &aad, &sealed, &tag, &out);
        expect(opened.len).toBe(114);
        expect(opened[0]).toBe('L');
    }

    test("should reject the wrong key or nonce") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = 3;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 4;
        let sealed: u8[3] = undefined;
        const tag = try chacha20Poly1305Seal(&key, &nonce, "", "abc", &sealed);
        let out: u8[3] = undefined;
        nonce[11] ^= 1;
        expect(chacha20Poly1305Open(&key, &nonce, "", &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        nonce[11] ^= 1;
        key[0] ^= 1;
        expect(chacha20Poly1305Open(&key, &nonce, "", &sealed, &tag, &out)).toThrow(AeadError.BadTag);
    }

    test("should reject a truncated or empty tag") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = 3;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 4;
        let sealed: u8[3] = undefined;
        const tag = try chacha20Poly1305Seal(&key, &nonce, "", "abc", &sealed);
        let out: u8[3] = undefined;
        expect(chacha20Poly1305Open(&key, &nonce, "", &sealed, tag[0..15], &out)).toThrow(AeadError.BadTag);
        expect(chacha20Poly1305Open(&key, &nonce, "", &sealed, "", &out)).toThrow(AeadError.BadTag);
    }

    test("should reject a key, a nonce, or a buffer of the wrong length") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = 0;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        let tag: u8[16] = undefined;
        for (const _, i of tag) tag[i] = 0;
        let out: u8[2] = undefined;
        expect(chacha20Poly1305Open(key[0..16], &nonce, "", "abc", &tag, &out)).toThrow(AeadError.BadKeyLength);
        expect(chacha20Poly1305Open(&key, nonce[0..8], "", "abc", &tag, &out)).toThrow(AeadError.BadNonceLength);
        expect(chacha20Poly1305Open(&key, &nonce, "", "abc", &tag, &out)).toThrow(AeadError.ShortBuffer);
    }
}
