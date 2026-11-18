/**
 * Imports
 */

import { decodeHex, encodeHex } from "@hex";
import { Aes, AesError } from "@aes";

/**
 * Encrypts one hex block under a hex key and writes the result as hex.
 *
 * @param keyHex - The key, as 32, 48, or 64 hex digits
 * @param blockHex - The block, as 32 hex digits
 * @param digits - The buffer for the 32 digits of the result
 * @returns The part of `digits` that holds the ciphertext block
 *
 * @remarks
 * It lets each vector of FIPS 197 read as its key, its plaintext, and its ciphertext.
 *
 * @since 1.0.0
 */

function encryptHex(keyHex: readonly u8[], blockHex: readonly u8[], digits: u8[]): u8[] | Error {
    let keyBytes: u8[32] = undefined;
    const key = try decodeHex(keyHex, &keyBytes);
    let block: u8[16] = undefined;
    void try decodeHex(blockHex, &block);
    const aes = try Aes.init(key);
    const sealed = aes.encryptBlock(block);
    return try encodeHex(&sealed, digits);
}

/**
 * Tests
 */

describe("Aes") {
    test("should match AES-128 of FIPS 197, appendix C.1") {
        let digits: u8[32] = undefined;
        const text: string = try encryptHex(
            "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", &digits,
        );
        expect(text).toBe("69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    test("should match AES-192 of FIPS 197, appendix C.2") {
        let digits: u8[32] = undefined;
        const text: string = try encryptHex(
            "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", &digits,
        );
        expect(text).toBe("dda97ca4864cdfe06eaf70a0ec0d7191");
    }

    test("should match AES-256 of FIPS 197, appendix C.3") {
        let digits: u8[32] = undefined;
        const text: string = try encryptHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff",
            &digits,
        );
        expect(text).toBe("8ea2b7ca516745bfeafc49904b496089");
    }

    test("should match the worked example of FIPS 197, appendix B") {
        let digits: u8[32] = undefined;
        const text: string = try encryptHex(
            "2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", &digits,
        );
        expect(text).toBe("3925841d02dc09fbdc118597196a0b32");
    }

    test("should encrypt the zero block under the zero key, as GCM's hash key") {
        let digits: u8[32] = undefined;
        const text: string = try encryptHex(
            "00000000000000000000000000000000", "00000000000000000000000000000000", &digits,
        );
        expect(text).toBe("66e94bd4ef8a2c3b884cfa59ca342b2e");
    }

    test("should expand the keys of FIPS 197, appendix A, to their last round keys") {
        let key128: u8[16] = undefined;
        void try decodeHex("2b7e151628aed2a6abf7158809cf4f3c", &key128);
        const aes128 = try Aes.init(&key128);
        expect(aes128.rounds).toBe(10);
        const keys128 = aes128.roundKeys;
        let digits128: u8[32] = undefined;
        const last128: string = try encodeHex(keys128[160..176], &digits128);
        expect(last128).toBe("d014f9a8c9ee2589e13f0cc8b6630ca6");

        let key192: u8[24] = undefined;
        void try decodeHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", &key192);
        const aes192 = try Aes.init(&key192);
        expect(aes192.rounds).toBe(12);
        const keys192 = aes192.roundKeys;
        let digits192: u8[32] = undefined;
        const last192: string = try encodeHex(keys192[192..208], &digits192);
        expect(last192).toBe("e98ba06f448c773c8ecc720401002202");

        let key256: u8[32] = undefined;
        void try decodeHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", &key256);
        const aes256 = try Aes.init(&key256);
        expect(aes256.rounds).toBe(14);
        const keys256 = aes256.roundKeys;
        let digits256: u8[32] = undefined;
        const last256: string = try encodeHex(keys256[224..240], &digits256);
        expect(last256).toBe("fe4890d1e6188d0b046df344706c631e");
    }

    test("should keep the first round key equal to the key") {
        let key: u8[16] = undefined;
        void try decodeHex("2b7e151628aed2a6abf7158809cf4f3c", &key);
        const aes = try Aes.init(&key);
        for (const byte, i of key) expect(aes.roundKeys[i]).toBe(byte);
    }

    test("should reject a key of any other length") {
        let key: u8[33] = undefined;
        for (const _, i of key) key[i] = 0;
        expect(Aes.init("")).toThrow(AesError.BadKeyLength);
        expect(Aes.init(key[0..15])).toThrow(AesError.BadKeyLength);
        expect(Aes.init(key[0..17])).toThrow(AesError.BadKeyLength);
        expect(Aes.init(key[0..20])).toThrow(AesError.BadKeyLength);
        expect(Aes.init(key[0..31])).toThrow(AesError.BadKeyLength);
        expect(Aes.init(&key)).toThrow(AesError.BadKeyLength);
    }
}
