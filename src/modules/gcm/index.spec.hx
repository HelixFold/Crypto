/**
 * Imports
 */

import { AeadError } from "@aead";
import { decodeHex, encodeHex } from "@hex";
import { aesGcmOpen, aesGcmSeal } from "@gcm";

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
 * Seals a message under hex parameters and writes the tag as hex.
 *
 * @param keyHex - The key, as 32 or 64 hex digits
 * @param nonceHex - The nonce, as 24 hex digits
 * @param aadHex - The associated data, as up to 40 hex digits
 * @param plaintext - The message
 * @param out - The buffer for the ciphertext
 * @param digits - The buffer for the 32 digits of the tag
 * @returns The part of `digits` that holds the tag
 *
 * @remarks
 * It lets each GCM test case read as its key, its nonce, its associated data, and its results.
 *
 * @since 1.0.0
 */

function sealHex(
    keyHex: readonly u8[], nonceHex: readonly u8[], aadHex: readonly u8[], plaintext: readonly u8[], out: u8[],
    digits: u8[],
): u8[] | Error {
    let keyBytes: u8[32] = undefined;
    const key = try decodeHex(keyHex, &keyBytes);
    let nonce: u8[12] = undefined;
    void try decodeHex(nonceHex, &nonce);
    let aadBytes: u8[20] = undefined;
    const aad = try decodeHex(aadHex, &aadBytes);
    const tag = try aesGcmSeal(key, &nonce, aad, plaintext, out);
    return try encodeHex(&tag, digits);
}

/**
 * Opens a message under hex parameters.
 *
 * @param keyHex - The key, as 32 or 64 hex digits
 * @param nonceHex - The nonce, as 24 hex digits
 * @param aadHex - The associated data, as up to 40 hex digits
 * @param ciphertext - The ciphertext
 * @param tagHex - The tag, as 32 hex digits
 * @param out - The buffer for the plaintext
 * @returns The part of `out` that holds the plaintext
 *
 * @remarks
 * It pairs with {@link sealHex}, so each test case checks both directions.
 *
 * @since 1.0.0
 */

function openHex(
    keyHex: readonly u8[], nonceHex: readonly u8[], aadHex: readonly u8[], ciphertext: readonly u8[],
    tagHex: readonly u8[], out: u8[],
): u8[] | Error {
    let keyBytes: u8[32] = undefined;
    const key = try decodeHex(keyHex, &keyBytes);
    let nonce: u8[12] = undefined;
    void try decodeHex(nonceHex, &nonce);
    let aadBytes: u8[20] = undefined;
    const aad = try decodeHex(aadHex, &aadBytes);
    let tag: u8[16] = undefined;
    void try decodeHex(tagHex, &tag);
    return try aesGcmOpen(key, &nonce, aad, ciphertext, &tag, out);
}

/**
 * Tests
 */

describe("aesGcmSeal") {
    test("should match test cases 1 and 13, with nothing to encrypt or authenticate") {
        let out: u8[1] = undefined;
        let digits: u8[32] = undefined;
        const zero128 = "00000000000000000000000000000000";
        const zero256 = "0000000000000000000000000000000000000000000000000000000000000000";
        const nonce = "000000000000000000000000";
        const one: string = try sealHex(zero128, nonce, "", "", &out, &digits);
        expect(one).toBe("58e2fccefa7e3061367f1d57a4e7455a");
        let moreDigits: u8[32] = undefined;
        const thirteen: string = try sealHex(zero256, nonce, "", "", &out, &moreDigits);
        expect(thirteen).toBe("530f8afbc74536b9a963b4f1c4cb738b");
    }

    test("should match test cases 2 and 14, with one zero block") {
        let zeros: u8[16] = undefined;
        for (const _, i of zeros) zeros[i] = 0;
        const nonce = "000000000000000000000000";
        let out: u8[16] = undefined;
        let digits: u8[32] = undefined;
        const two: string = try sealHex("00000000000000000000000000000000", nonce, "", &zeros, &out, &digits);
        expect(two).toBe("ab6e47d42cec13bdf53a67b21257bddf");
        let cipherDigits: u8[32] = undefined;
        const twoCipher: string = try encodeHex(&out, &cipherDigits);
        expect(twoCipher).toBe("0388dace60b6a392f328c2b971b2fe78");

        const zero256 = "0000000000000000000000000000000000000000000000000000000000000000";
        let moreDigits: u8[32] = undefined;
        const fourteen: string = try sealHex(zero256, nonce, "", &zeros, &out, &moreDigits);
        expect(fourteen).toBe("d0d1c8a799996bf0265b98b5d48ab919");
        let moreCipherDigits: u8[32] = undefined;
        const fourteenCipher: string = try encodeHex(&out, &moreCipherDigits);
        expect(fourteenCipher).toBe("cea7403d4d606b6e074ec5d3baf39d18");
    }

    test("should match test case 3, four full blocks under AES-128") {
        const plainRows: string[2] = [
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        ];
        let plainBuffer: u8[64] = undefined;
        const plain = try decodeRows(&plainRows, &plainBuffer);
        let out: u8[64] = undefined;
        let digits: u8[32] = undefined;
        const key = "feffe9928665731c6d6a8f9467308308";
        const tag: string = try sealHex(key, "cafebabefacedbaddecaf888", "", plain, &out, &digits);
        expect(tag).toBe("4d5c2af327cd64a62cf35abd2ba6fab4");
        const rows: string[2] = [
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        ];
        for (const row, i of rows) {
            let rowDigits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(&out, i), &rowDigits);
            expect(text).toBe(row);
        }
    }

    test("should match test case 4, a partial block and associated data under AES-128") {
        const plainRows: string[2] = [
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        ];
        let plainBuffer: u8[60] = undefined;
        const plain = try decodeRows(&plainRows, &plainBuffer);
        let out: u8[60] = undefined;
        let digits: u8[32] = undefined;
        const key = "feffe9928665731c6d6a8f9467308308";
        const aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        const tag: string = try sealHex(key, "cafebabefacedbaddecaf888", aad, plain, &out, &digits);
        expect(tag).toBe("5bc94fbc3221a5db94fae95ae7121a47");
        const rows: string[2] = [
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        ];
        for (const row, i of rows) {
            let rowDigits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(&out, i), &rowDigits);
            expect(text).toBe(row);
        }
    }

    test("should match test case 15, four full blocks under AES-256") {
        const plainRows: string[2] = [
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        ];
        let plainBuffer: u8[64] = undefined;
        const plain = try decodeRows(&plainRows, &plainBuffer);
        let out: u8[64] = undefined;
        let digits: u8[32] = undefined;
        const key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        const tag: string = try sealHex(key, "cafebabefacedbaddecaf888", "", plain, &out, &digits);
        expect(tag).toBe("b094dac5d93471bdec1a502270e3cc6c");
        const rows: string[2] = [
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        ];
        for (const row, i of rows) {
            let rowDigits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(&out, i), &rowDigits);
            expect(text).toBe(row);
        }
    }

    test("should match test case 16, a partial block and associated data under AES-256") {
        const plainRows: string[2] = [
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        ];
        let plainBuffer: u8[60] = undefined;
        const plain = try decodeRows(&plainRows, &plainBuffer);
        let out: u8[60] = undefined;
        let digits: u8[32] = undefined;
        const key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        const aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        const tag: string = try sealHex(key, "cafebabefacedbaddecaf888", aad, plain, &out, &digits);
        expect(tag).toBe("76fc6ece0f4e1768cddf8853bb2d551b");
        const rows: string[2] = [
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        ];
        for (const row, i of rows) {
            let rowDigits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(&out, i), &rowDigits);
            expect(text).toBe(row);
        }
    }

    test("should seal a message shorter than one block") {
        let out: u8[3] = undefined;
        let digits: u8[32] = undefined;
        const key = "feffe9928665731c6d6a8f9467308308";
        const aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        const tag: string = try sealHex(key, "cafebabefacedbaddecaf888", aad, "abc", &out, &digits);
        expect(tag).toBe("f8729b78481ea28a0bea015c40d0679c");
        let cipherDigits: u8[6] = undefined;
        const cipherText: string = try encodeHex(&out, &cipherDigits);
        expect(cipherText).toBe("fad04f");
    }

    test("should reject a key, a nonce, or a buffer of the wrong length") {
        let key: u8[33] = undefined;
        for (const _, i of key) key[i] = 0;
        let nonce: u8[16] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        let out: u8[3] = undefined;
        expect(aesGcmSeal(key[0..15], nonce[0..12], "", "abc", &out)).toThrow(AeadError.BadKeyLength);
        expect(aesGcmSeal(key[0..20], nonce[0..12], "", "abc", &out)).toThrow(AeadError.BadKeyLength);
        expect(aesGcmSeal(&key, nonce[0..12], "", "abc", &out)).toThrow(AeadError.BadKeyLength);
        expect(aesGcmSeal(key[0..16], nonce[0..8], "", "abc", &out)).toThrow(AeadError.BadNonceLength);
        expect(aesGcmSeal(key[0..16], &nonce, "", "abc", &out)).toThrow(AeadError.BadNonceLength);
        expect(aesGcmSeal(key[0..16], nonce[0..12], "", "abcd", &out)).toThrow(AeadError.ShortBuffer);
    }
}

describe("aesGcmOpen") {
    test("should open test case 4 and give back its plaintext") {
        const cipherRows: string[2] = [
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        ];
        let cipherBuffer: u8[60] = undefined;
        const ciphertext = try decodeRows(&cipherRows, &cipherBuffer);
        let out: u8[60] = undefined;
        const key = "feffe9928665731c6d6a8f9467308308";
        const aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        const tag = "5bc94fbc3221a5db94fae95ae7121a47";
        const plain = try openHex(key, "cafebabefacedbaddecaf888", aad, ciphertext, tag, &out);
        expect(plain.len).toBe(60);
        const rows: string[2] = [
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        ];
        for (const row, i of rows) {
            let rowDigits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(plain, i), &rowDigits);
            expect(text).toBe(row);
        }
    }

    test("should open test case 16 and give back its plaintext") {
        const cipherRows: string[2] = [
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        ];
        let cipherBuffer: u8[60] = undefined;
        const ciphertext = try decodeRows(&cipherRows, &cipherBuffer);
        let out: u8[60] = undefined;
        const key = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        const aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        const tag = "76fc6ece0f4e1768cddf8853bb2d551b";
        const plain = try openHex(key, "cafebabefacedbaddecaf888", aad, ciphertext, tag, &out);
        const rows: string[2] = [
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        ];
        for (const row, i of rows) {
            let rowDigits: u8[64] = undefined;
            const text: string = try encodeHex(rowOf(plain, i), &rowDigits);
            expect(text).toBe(row);
        }
    }

    test("should open test case 1, with nothing to decrypt") {
        let out: u8[1] = undefined;
        const key = "00000000000000000000000000000000";
        const tag = "58e2fccefa7e3061367f1d57a4e7455a";
        const plain = try openHex(key, "000000000000000000000000", "", "", tag, &out);
        expect(plain.len).toBe(0);
    }

    test("should give back what was sealed, under every key length, in place") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = i as u8;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 0x5A;
        const message = "a message that ends partway through its third block";
        const lengths: usize[3] = [16, 24, 32];
        for (const length of lengths) {
            let buffer: u8[51] = undefined;
            for (const byte, i of message) buffer[i] = byte;
            const tag = try aesGcmSeal(key[0..length], &nonce, "header", &buffer, &buffer);
            const plain = try aesGcmOpen(key[0..length], &nonce, "header", &buffer, &tag, &buffer);
            const text: string = plain;
            expect(text).toBe(message);
        }
    }

    test("should reject a changed ciphertext, tag, or associated data, and release nothing") {
        let key: u8[16] = undefined;
        void try decodeHex("feffe9928665731c6d6a8f9467308308", &key);
        let nonce: u8[12] = undefined;
        void try decodeHex("cafebabefacedbaddecaf888", &nonce);
        let aad: u8[20] = undefined;
        void try decodeHex("feedfacedeadbeeffeedfacedeadbeefabaddad2", &aad);
        const message = "a message of forty bytes, two and a half";
        let sealed: u8[40] = undefined;
        let tag = try aesGcmSeal(&key, &nonce, &aad, message, &sealed);
        let out: u8[40] = undefined;
        for (const _, i of out) out[i] = 0xAA;

        sealed[39] ^= 0x01;
        expect(aesGcmOpen(&key, &nonce, &aad, &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        sealed[39] ^= 0x01;
        sealed[0] ^= 0x80;
        expect(aesGcmOpen(&key, &nonce, &aad, &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        sealed[0] ^= 0x80;

        tag[0] ^= 0x01;
        expect(aesGcmOpen(&key, &nonce, &aad, &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        tag[0] ^= 0x01;

        aad[19] ^= 0x01;
        expect(aesGcmOpen(&key, &nonce, &aad, &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        aad[19] ^= 0x01;
        expect(aesGcmOpen(&key, &nonce, aad[0..19], &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        expect(aesGcmOpen(&key, &nonce, "", &sealed, &tag, &out)).toThrow(AeadError.BadTag);

        nonce[0] ^= 0x01;
        expect(aesGcmOpen(&key, &nonce, &aad, &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        nonce[0] ^= 0x01;
        key[15] ^= 0x01;
        expect(aesGcmOpen(&key, &nonce, &aad, &sealed, &tag, &out)).toThrow(AeadError.BadTag);
        key[15] ^= 0x01;

        expect(aesGcmOpen(&key, &nonce, &aad, &sealed, tag[0..12], &out)).toThrow(AeadError.BadTag);
        expect(aesGcmOpen(&key, &nonce, &aad, &sealed, "", &out)).toThrow(AeadError.BadTag);

        for (const byte of out) expect(byte).toBe(0xAA);

        const plain = try aesGcmOpen(&key, &nonce, &aad, &sealed, &tag, &out);
        const text: string = plain;
        expect(text).toBe(message);
    }

    test("should reject a key, a nonce, or a buffer of the wrong length") {
        let key: u8[16] = undefined;
        for (const _, i of key) key[i] = 0;
        let nonce: u8[12] = undefined;
        for (const _, i of nonce) nonce[i] = 0;
        let tag: u8[16] = undefined;
        for (const _, i of tag) tag[i] = 0;
        let out: u8[2] = undefined;
        expect(aesGcmOpen(key[0..8], &nonce, "", "abc", &tag, &out)).toThrow(AeadError.BadKeyLength);
        expect(aesGcmOpen(&key, nonce[0..11], "", "abc", &tag, &out)).toThrow(AeadError.BadNonceLength);
        expect(aesGcmOpen(&key, &nonce, "", "abc", &tag, &out)).toThrow(AeadError.ShortBuffer);
    }
}
