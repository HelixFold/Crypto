/**
 * Imports
 */

import { decodeHex, encodeHex } from "@hex";
import { ChaCha20Error, chacha20, chacha20Block } from "@chacha20";

/**
 * Copies strings one after another into a buffer.
 *
 * @param parts - The strings, in order
 * @param out - The buffer, at least as long as all of them together
 * @returns The part of `out` that holds the joined bytes
 *
 * @remarks
 * It keeps long test messages within the line limit by splitting them into short literals.
 *
 * @since 1.0.0
 */

function join(parts: readonly string[], out: u8[]): u8[] {
    let at: usize = 0;
    for (const part of parts) {
        for (const byte, i of part) out[at + i] = byte;
        at += part.len;
    }
    return out[0..at];
}

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
 * Tests
 */

describe("chacha20Block") {
    test("should match the block of RFC 8439, section 2.3.2") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = i as u8;
        let nonce: u8[12] = undefined;
        void try decodeHex("000000090000004a00000000", &nonce);
        const stream = try chacha20Block(&key, &nonce, 1);
        const rows: string[2] = [
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e",
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        ];
        for (const row, i of rows) {
            let digits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(&stream, i), &digits);
            expect(text).toBe(row);
        }
    }

    test("should match the zero key blocks of RFC 8439, appendix A.1") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = 0;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        const first = try chacha20Block(&key, &nonce, 0);
        const second = try chacha20Block(&key, &nonce, 1);
        const firstRows: string[2] = [
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
            "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
        ];
        const secondRows: string[2] = [
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed",
            "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
        ];
        for (const row, i of firstRows) {
            let digits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(&first, i), &digits);
            expect(text).toBe(row);
        }
        for (const row, i of secondRows) {
            let digits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(&second, i), &digits);
            expect(text).toBe(row);
        }
    }

    test("should give the Poly1305 key of RFC 8439, section 2.6.2") {
        let key: u8[32] = undefined;
        void try decodeHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", &key);
        let nonce: u8[12] = undefined;
        void try decodeHex("000000000001020304050607", &nonce);
        const stream = try chacha20Block(&key, &nonce, 0);
        let digits: u8[64] = undefined;
        const text: string = try encodeHex(stream[0..32], &digits);
        expect(text).toBe("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646");
    }

    test("should reject a key or a nonce of the wrong length") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = 0;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        expect(chacha20Block(key[0..31], &nonce, 0)).toThrow(ChaCha20Error.BadKeyLength);
        expect(chacha20Block("", &nonce, 0)).toThrow(ChaCha20Error.BadKeyLength);
        expect(chacha20Block(&key, nonce[0..8], 0)).toThrow(ChaCha20Error.BadNonceLength);
    }
}

describe("chacha20") {
    test("should match the encryption of RFC 8439, section 2.4.2") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = i as u8;
        let nonce: u8[12] = undefined;
        void try decodeHex("000000000000004a00000000", &nonce);
        const parts: string[2] = [
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for ",
            "the future, sunscreen would be it.",
        ];
        let buffer: u8[114] = undefined;
        const plain = join(&parts, &buffer);
        let out: u8[114] = undefined;
        const sealed = try chacha20(&key, &nonce, 1, plain, &out);
        expect(sealed.len).toBe(114);
        const rows: string[4] = [
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b",
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8",
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736",
            "5af90bbf74a35be6b40b8eedf2785e42874d",
        ];
        for (const row, i of rows) {
            let digits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(sealed, i), &digits);
            expect(text).toBe(row);
        }
    }

    test("should decrypt the Jabberwocky of RFC 8439, appendix A.2, from counter 42") {
        let key: u8[32] = undefined;
        void try decodeHex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", &key);
        let nonce: u8[12] = undefined;
        void try decodeHex("000000000000000000000002", &nonce);
        const rows: string[4] = [
            "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf",
            "166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb",
            "f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77",
            "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
        ];
        let buffer: u8[127] = undefined;
        const sealed = try decodeRows(&rows, &buffer);
        let out: u8[127] = undefined;
        const plain = try chacha20(&key, &nonce, 42, sealed, &out);
        const parts: string[4] = [
            "'Twas brillig, and the slithy toves\n",
            "Did gyre and gimble in the wabe:\n",
            "All mimsy were the borogoves,\n",
            "And the mome raths outgrabe.",
        ];
        let expected: u8[127] = undefined;
        const lines = join(&parts, &expected);
        expect(plain.len).toBe(127);
        for (const byte, i of lines) expect(plain[i]).toBe(byte);
    }

    test("should give back the plaintext when run twice") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = i as u8;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 7;
        const message = "a message that runs past one block of sixty-four bytes and well into the second: 90 bytes!";
        let sealed: u8[90] = undefined;
        let opened: u8[90] = undefined;
        const ciphertext = try chacha20(&key, &nonce, 5, message, &sealed);
        const plain = try chacha20(&key, &nonce, 5, ciphertext, &opened);
        const text: string = plain;
        expect(text).toBe(message);
    }

    test("should allow the output to be the input buffer") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = i as u8;
        let nonce: u8[12] = undefined;
        void try decodeHex("000000000000004a00000000", &nonce);
        let buffer: u8[9] = undefined;
        for (const byte, i of "in place!") buffer[i] = byte;
        void try chacha20(&key, &nonce, 1, &buffer, &buffer);
        let digits: u8[18] = undefined;
        const text: string = try encodeHex(&buffer, &digits);
        let reference: u8[9] = undefined;
        const sealed = try chacha20(&key, &nonce, 1, "in place!", &reference);
        let referenceDigits: u8[18] = undefined;
        const expected: string = try encodeHex(sealed, &referenceDigits);
        expect(text).toBe(expected);
    }

    test("should write nothing for no input, even at the last counter") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = 0;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        let out: u8[4] = undefined;
        const first = try chacha20(&key, &nonce, 0, "", &out);
        expect(first.len).toBe(0);
        const last = try chacha20(&key, &nonce, 0xFFFF_FFFF, "", &out);
        expect(last.len).toBe(0);
    }

    test("should let the last block use counter 0xFFFFFFFF") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = i as u8;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        let zeros: u8[64] = undefined;
        for (const _, i of zeros) zeros[i] = 0;
        let out: u8[64] = undefined;
        const stream = try chacha20(&key, &nonce, 0xFFFF_FFFF, &zeros, &out);
        const rows: string[2] = [
            "1ce0deb8925fccea2d5587e850054559edcbbeb1a6c8e1c02c1e89abba08b01c",
            "ad6048fe5ab5242ed6befbef6b4040fcb666a5f3858d942a912c4e8800301a42",
        ];
        for (const row, i of rows) {
            let digits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(stream, i), &digits);
            expect(text).toBe(row);
        }
    }

    test("should reject input that would wrap the counter") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = 0;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        let input: u8[65] = undefined;
        for (const _, i of input) input[i] = 0;
        let out: u8[129] = undefined;
        expect(chacha20(&key, &nonce, 0xFFFF_FFFF, &input, &out)).toThrow(ChaCha20Error.CounterOverflow);
        expect(chacha20(&key, &nonce, 0xFFFF_FFFE, &out, &out)).toThrow(ChaCha20Error.CounterOverflow);
    }

    test("should reject a buffer that is too small") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = 0;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        let out: u8[2] = undefined;
        expect(chacha20(&key, &nonce, 0, "abc", &out)).toThrow(ChaCha20Error.ShortBuffer);
    }

    test("should reject a key or a nonce of the wrong length") {
        let key: u8[33] = undefined;
        for (const _, i of key) key[i] = 0;
        let nonce: u8[13] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        let out: u8[4] = undefined;
        expect(chacha20(&key, nonce[0..12], 0, "abc", &out)).toThrow(ChaCha20Error.BadKeyLength);
        expect(chacha20(key[0..32], &nonce, 0, "abc", &out)).toThrow(ChaCha20Error.BadNonceLength);
    }
}
