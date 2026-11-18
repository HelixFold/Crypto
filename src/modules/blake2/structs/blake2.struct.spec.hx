/**
 * Imports
 */

import { encodeHex } from "@hex";
import { Blake2Error } from "@blake2/errors/blake2.error";
import { Blake2b, Blake2s } from "@blake2/structs/blake2.struct";

/**
 * Tests
 */

describe("Blake2b") {
    test("should finish to the digest of no bytes") {
        const hash = try Blake2b.init(64, "");
        let digestBuf: u8[64] = undefined;
        const digest = try hash.finish(&digestBuf);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    }

    test("should give the same digest wherever the 896-bit message is split") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = try Blake2b.init(64, "");
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            let digestBuf: u8[64] = undefined;
            const digest = try hash.finish(&digestBuf);
            const text: string = try encodeHex(digest, &out);
            expect(text).toBe("ce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = try Blake2b.init(64, "");
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        let digestBuf: u8[64] = undefined;
        const digest = try hash.finish(&digestBuf);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("ce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52");
    }

    test("should keep the state when finishing") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = try Blake2b.init(64, "");
        hash.update(message[0..32]);
        let earlyBuf: u8[64] = undefined;
        const early = try hash.finish(&earlyBuf);
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(early, &out);
        expect(earlyText).toBe("f8d872c105ee6081da6541ef1e25f288be8fb775e0219fd06943d3c8e087edab0887337f7027c429003325345d82494efc4c68634078b0e07d8d96b0e75202b4");
        hash.update(message[32..message.len]);
        let digestBuf: u8[64] = undefined;
        const digest = try hash.finish(&digestBuf);
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("ce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = try Blake2b.init(64, "");
        for (const _ of 0..1000) hash.update(&chunk);
        let digestBuf: u8[64] = undefined;
        const digest = try hash.finish(&digestBuf);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1d077609d7fba363cbba00d05f7aa4e4fa8715d6428104c0a75643b0ff3fd3eaf");
    }

    test("should fold the parameters into the state and keep a full block waiting") {
        let hash = try Blake2b.init(64, "");
        expect(hash.state[0]).toBe(0x6a09e667f2bdc948);
        expect(hash.outLen).toBe(64);
        let bytes: u8[129] = undefined;
        for (const i of 0..129) bytes[i] = 'a';
        hash.update(bytes[0..128]);
        expect(hash.used).toBe(128);
        expect(hash.count).toBe(0);
        hash.update(bytes[128..129]);
        expect(hash.used).toBe(1);
        expect(hash.count).toBe(128);
        expect(hash.countHigh).toBe(0);
    }

    test("should hash with a key of 64 bytes") {
        let key: u8[64] = undefined;
        for (const i of 0..64) key[i] = i as u8;
        let out: u8[128] = undefined;
        let emptyHash = try Blake2b.init(64, &key);
        emptyHash.update("");
        let emptyDigestBuf: u8[64] = undefined;
        const emptyDigest = try emptyHash.finish(&emptyDigestBuf);
        const emptyText: string = try encodeHex(emptyDigest, &out);
        expect(emptyText).toBe("10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568");
        let abcHash = try Blake2b.init(64, &key);
        abcHash.update("abc");
        let abcDigestBuf: u8[64] = undefined;
        const abcDigest = try abcHash.finish(&abcDigestBuf);
        const abcText: string = try encodeHex(abcDigest, &out);
        expect(abcText).toBe("06bbc3dedf13a31139498655251b7588ccd3bb5aaa071b2d44d8e0a04095579ed590fbfdcf941f4370ce5ce623624e7a76d33e7a8109dcda9b57d72f8f8efa51");
    }

    test("should hash the bytes 0 to 255 under a key, as the RFC 7693 test suite does") {
        let key: u8[64] = undefined;
        for (const i of 0..64) key[i] = i as u8;
        let message: u8[256] = undefined;
        for (const i of 0..256) message[i] = i as u8;
        let out: u8[128] = undefined;
        let hash = try Blake2b.init(64, &key);
        hash.update(&message);
        let digestBuf: u8[64] = undefined;
        const digest = try hash.finish(&digestBuf);
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("b72071e096277edebb8ee5134dd3714996307ba3a55aa4733d412abbe28e909e10e57e6fbfb4ef53b3b960518294ff889a90829254412e2a60b85add07a3674f");
    }

    test("should hash exactly one block after the key block") {
        let key: u8[64] = undefined;
        for (const i of 0..64) key[i] = i as u8;
        let message: u8[128] = undefined;
        for (const i of 0..128) message[i] = 'a';
        let out: u8[128] = undefined;
        let hash = try Blake2b.init(64, &key);
        hash.update(&message);
        let digestBuf: u8[64] = undefined;
        const digest = try hash.finish(&digestBuf);
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("9792d5d15fd64e3604791412c384bd664158fd0d4d91f9798201ac1b71108e4762baf64472d6a682b2a40e51133b570e2379e0654a4e2c2ffe6c4240c123a87c");
    }

    test("should give the same keyed digest wherever the message is split") {
        let key: u8[64] = undefined;
        for (const i of 0..64) key[i] = i as u8;
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = try Blake2b.init(64, &key);
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            let digestBuf: u8[64] = undefined;
            const digest = try hash.finish(&digestBuf);
            const text: string = try encodeHex(digest, &out);
            expect(text).toBe("cfdc2d58a48f7e616a5a293907863d53a830e135d437f164e7fa39ab73efbeefc32f29742d745b952c05253581df913a91dc74dd817609bac1617f1b026abc16");
        }
    }

    test("should give shorter outputs that are not prefixes of the full one") {
        let out: u8[128] = undefined;
        let hash1 = try Blake2b.init(1, "");
        hash1.update("abc");
        let digest1Buf: u8[64] = undefined;
        const digest1 = try hash1.finish(&digest1Buf);
        expect(digest1.len).toBe(1);
        const text1: string = try encodeHex(digest1, &out);
        expect(text1).toBe("6b");
        let hash20 = try Blake2b.init(20, "");
        hash20.update("abc");
        let digest20Buf: u8[64] = undefined;
        const digest20 = try hash20.finish(&digest20Buf);
        expect(digest20.len).toBe(20);
        const text20: string = try encodeHex(digest20, &out);
        expect(text20).toBe("384264f676f39536840523f284921cdc68b6846b");
        let hash32 = try Blake2b.init(32, "");
        hash32.update("abc");
        let digest32Buf: u8[64] = undefined;
        const digest32 = try hash32.finish(&digest32Buf);
        expect(digest32.len).toBe(32);
        const text32: string = try encodeHex(digest32, &out);
        expect(text32).toBe("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
        let hash48 = try Blake2b.init(48, "");
        hash48.update("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let digest48Buf: u8[64] = undefined;
        const digest48 = try hash48.finish(&digest48Buf);
        const text48: string = try encodeHex(digest48, &out);
        expect(text48).toBe("5643daabfc919190d373a3d58935804d731b58812f30184f98793f7321d0cb34bb41b217fabce6bdf28ca6be1c923b81");
    }

    test("should combine a short key with a short output") {
        let hash = try Blake2b.init(32, "key");
        hash.update("abc");
        let digestBuf: u8[64] = undefined;
        const digest = try hash.finish(&digestBuf);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("0330531d097355a3f72e80d55c1245ccf79f1704431c6e3887938320442c23c0");
    }

    test("should write only the output length into a longer buffer") {
        let hash = try Blake2b.init(20, "");
        hash.update("abc");
        let buffer: u8[64] = undefined;
        for (const i of 0..64) buffer[i] = 0xEE;
        const digest = try hash.finish(&buffer);
        expect(digest.len).toBe(20);
        expect(buffer[20]).toBe(0xEE);
        expect(buffer[63]).toBe(0xEE);
    }

    test("should reject an output length of 0 or above 64") {
        expect(Blake2b.init(0, "")).toThrow(Blake2Error.BadOutputLength);
        expect(Blake2b.init(65, "")).toThrow(Blake2Error.BadOutputLength);
    }

    test("should reject a key longer than 64 bytes") {
        let key: u8[65] = undefined;
        for (const i of 0..65) key[i] = 0;
        expect(Blake2b.init(64, &key)).toThrow(Blake2Error.BadKeyLength);
        expect(Blake2b.init(64, key[0..64])).toSucceed();
    }

    test("should reject a buffer shorter than the output length") {
        const hash = try Blake2b.init(32, "");
        let small: u8[31] = undefined;
        expect(hash.finish(&small)).toThrow(Blake2Error.ShortBuffer);
    }
}

describe("Blake2s") {
    test("should finish to the digest of no bytes") {
        const hash = try Blake2s.init(32, "");
        let digestBuf: u8[32] = undefined;
        const digest = try hash.finish(&digestBuf);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    }

    test("should give the same digest wherever the 448-bit message is split") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = try Blake2s.init(32, "");
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            let digestBuf: u8[32] = undefined;
            const digest = try hash.finish(&digestBuf);
            const text: string = try encodeHex(digest, &out);
            expect(text).toBe("6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = try Blake2s.init(32, "");
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        let digestBuf: u8[32] = undefined;
        const digest = try hash.finish(&digestBuf);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("358dd2ed0780d4054e76cb6f3a5bce2841e8e2f547431d4d09db21b66d941fc7");
    }

    test("should keep the state when finishing") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = try Blake2s.init(32, "");
        hash.update(message[0..32]);
        let earlyBuf: u8[32] = undefined;
        const early = try hash.finish(&earlyBuf);
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(early, &out);
        expect(earlyText).toBe("5f7db3f84fca36b1a9a6f43a39eb26be7b9ad440ec398886068b3ebb01210572");
        hash.update(message[32..message.len]);
        let digestBuf: u8[32] = undefined;
        const digest = try hash.finish(&digestBuf);
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = try Blake2s.init(32, "");
        for (const _ of 0..1000) hash.update(&chunk);
        let digestBuf: u8[32] = undefined;
        const digest = try hash.finish(&digestBuf);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("bec0c0e6cde5b67acb73b81f79a67a4079ae1c60dac9d2661af18e9f8b50dfa5");
    }

    test("should fold the parameters into the state and keep a full block waiting") {
        let hash = try Blake2s.init(32, "");
        expect(hash.state[0]).toBe(0x6b08e647);
        expect(hash.outLen).toBe(32);
        let bytes: u8[65] = undefined;
        for (const i of 0..65) bytes[i] = 'a';
        hash.update(bytes[0..64]);
        expect(hash.used).toBe(64);
        expect(hash.count).toBe(0);
        hash.update(bytes[64..65]);
        expect(hash.used).toBe(1);
        expect(hash.count).toBe(64);
        expect(hash.countHigh).toBe(0);
    }

    test("should hash with a key of 32 bytes") {
        let key: u8[32] = undefined;
        for (const i of 0..32) key[i] = i as u8;
        let out: u8[128] = undefined;
        let emptyHash = try Blake2s.init(32, &key);
        emptyHash.update("");
        let emptyDigestBuf: u8[32] = undefined;
        const emptyDigest = try emptyHash.finish(&emptyDigestBuf);
        const emptyText: string = try encodeHex(emptyDigest, &out);
        expect(emptyText).toBe("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49");
        let abcHash = try Blake2s.init(32, &key);
        abcHash.update("abc");
        let abcDigestBuf: u8[32] = undefined;
        const abcDigest = try abcHash.finish(&abcDigestBuf);
        const abcText: string = try encodeHex(abcDigest, &out);
        expect(abcText).toBe("a281f725754969a702f6fe36fc591b7def866e4b70173ece402fc01c064d6b65");
    }

    test("should hash the bytes 0 to 255 under a key, as the RFC 7693 test suite does") {
        let key: u8[32] = undefined;
        for (const i of 0..32) key[i] = i as u8;
        let message: u8[256] = undefined;
        for (const i of 0..256) message[i] = i as u8;
        let out: u8[128] = undefined;
        let hash = try Blake2s.init(32, &key);
        hash.update(&message);
        let digestBuf: u8[32] = undefined;
        const digest = try hash.finish(&digestBuf);
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("5211d1aefc0025be7f85c06b3e14e0fc645ae12bd41746485ea6d8a364a2eaee");
    }

    test("should hash exactly one block after the key block") {
        let key: u8[32] = undefined;
        for (const i of 0..32) key[i] = i as u8;
        let message: u8[64] = undefined;
        for (const i of 0..64) message[i] = 'a';
        let out: u8[128] = undefined;
        let hash = try Blake2s.init(32, &key);
        hash.update(&message);
        let digestBuf: u8[32] = undefined;
        const digest = try hash.finish(&digestBuf);
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("623b3dfdccfa5a9ed76162694fbf7729f60d79cce1a49e89e9af17e4be91d2ab");
    }

    test("should give the same keyed digest wherever the message is split") {
        let key: u8[32] = undefined;
        for (const i of 0..32) key[i] = i as u8;
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = try Blake2s.init(32, &key);
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            let digestBuf: u8[32] = undefined;
            const digest = try hash.finish(&digestBuf);
            const text: string = try encodeHex(digest, &out);
            expect(text).toBe("e9d83cc21757b34060fd88d94f9542e0e2a30e1e3a3a06fc04665246f32b6077");
        }
    }

    test("should give shorter outputs that are not prefixes of the full one") {
        let out: u8[128] = undefined;
        let hash1 = try Blake2s.init(1, "");
        hash1.update("abc");
        let digest1Buf: u8[32] = undefined;
        const digest1 = try hash1.finish(&digest1Buf);
        expect(digest1.len).toBe(1);
        const text1: string = try encodeHex(digest1, &out);
        expect(text1).toBe("0d");
        let hash16 = try Blake2s.init(16, "");
        hash16.update("abc");
        let digest16Buf: u8[32] = undefined;
        const digest16 = try hash16.finish(&digest16Buf);
        expect(digest16.len).toBe(16);
        const text16: string = try encodeHex(digest16, &out);
        expect(text16).toBe("aa4938119b1dc7b87cbad0ffd200d0ae");
        let hash28 = try Blake2s.init(28, "");
        hash28.update("abc");
        let digest28Buf: u8[32] = undefined;
        const digest28 = try hash28.finish(&digest28Buf);
        expect(digest28.len).toBe(28);
        const text28: string = try encodeHex(digest28, &out);
        expect(text28).toBe("0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55");
        let hash24 = try Blake2s.init(24, "");
        hash24.update("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let digest24Buf: u8[32] = undefined;
        const digest24 = try hash24.finish(&digest24Buf);
        const text24: string = try encodeHex(digest24, &out);
        expect(text24).toBe("f70b2b7dd681e0652956cf63b57e0234a78aeca01ee5fad0");
    }

    test("should combine a short key with a short output") {
        let hash = try Blake2s.init(16, "key");
        hash.update("abc");
        let digestBuf: u8[32] = undefined;
        const digest = try hash.finish(&digestBuf);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(digest, &out);
        expect(text).toBe("94fdf6f35b9999920dcdcaee361ad435");
    }

    test("should write only the output length into a longer buffer") {
        let hash = try Blake2s.init(20, "");
        hash.update("abc");
        let buffer: u8[32] = undefined;
        for (const i of 0..32) buffer[i] = 0xEE;
        const digest = try hash.finish(&buffer);
        expect(digest.len).toBe(20);
        expect(buffer[20]).toBe(0xEE);
        expect(buffer[31]).toBe(0xEE);
    }

    test("should reject an output length of 0 or above 32") {
        expect(Blake2s.init(0, "")).toThrow(Blake2Error.BadOutputLength);
        expect(Blake2s.init(33, "")).toThrow(Blake2Error.BadOutputLength);
    }

    test("should reject a key longer than 32 bytes") {
        let key: u8[33] = undefined;
        for (const i of 0..33) key[i] = 0;
        expect(Blake2s.init(32, &key)).toThrow(Blake2Error.BadKeyLength);
        expect(Blake2s.init(32, key[0..32])).toSucceed();
    }

    test("should reject a buffer shorter than the output length") {
        const hash = try Blake2s.init(32, "");
        let small: u8[31] = undefined;
        expect(hash.finish(&small)).toThrow(Blake2Error.ShortBuffer);
    }
}
