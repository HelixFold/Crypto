/**
 * Imports
 */

import { encodeHex } from "@hex";
import { blake2b, blake2s } from "@blake2";

/**
 * Tests
 */

describe("blake2b") {
    test("should hash the empty message") {
        const digest = blake2b("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    }

    test("should hash the message abc") {
        const digest = blake2b("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    }

    test("should hash the 448-bit NIST message") {
        const digest = blake2b("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141ed1b3e4528595acc90772bdf2d37dc8a47130b44f33a02e8730e5ad8e166e888");
    }

    test("should hash the 896-bit NIST message") {
        const digest = blake2b("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("ce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52");
    }

    test("should hash runs of a around the block boundary of 128 bytes") {
        let bytes: u8[257] = undefined;
        for (const i of 0..257) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest127 = blake2b(bytes[0..127]);
        const text127: string = try encodeHex(&digest127, &out);
        expect(text127).toBe("94596b9d6199c807c40ae1a935f3633ba5a8dd5655f7f1bd44f5285b1ce8dbb0054771eba409539df85a963296d28788807105153c90fa3ec3d761228e90f8b8");
        const digest128 = blake2b(bytes[0..128]);
        const text128: string = try encodeHex(&digest128, &out);
        expect(text128).toBe("fc6c71f688f43ea7d60817478808f3cac753e61571865c95adbc2d9122c943a76b92c2cb1047ef3fe7bf6e436ec1d0a99a9e5b216780bf7fed9d7ca91d3a8f3b");
        const digest129 = blake2b(bytes[0..129]);
        const text129: string = try encodeHex(&digest129, &out);
        expect(text129).toBe("55e6e0eb418149a8af92fd9ddc99254781b2f522a131b4f4d984404b71a00e1167b8124d5dcddd4c6977b299392335d6edd303da6d344d74bbef2d38101b232b");
        const digest256 = blake2b(bytes[0..256]);
        const text256: string = try encodeHex(&digest256, &out);
        expect(text256).toBe("0eee13d0c73a2710c5015a8b4be0a16120bb88f826b662951ffe4b3b81441cfdce1f712c58e237dba72a0dad7f9c86b9745ea0b4b3b850ff3a260fb7df9d3e81");
        const digest257 = blake2b(bytes[0..257]);
        const text257: string = try encodeHex(&digest257, &out);
        expect(text257).toBe("0d686cbcff66401ab36b8a8e7fcf4085319eb296eaa55c4470c36bccaff2ecd4b3572c32ed48e8bb97cc5d08302a79b3a26e751feb7f565b19fa0d8f65247dd1");
    }
}

describe("blake2s") {
    test("should hash the empty message") {
        const digest = blake2s("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    }

    test("should hash the message abc") {
        const digest = blake2s("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    }

    test("should hash the 448-bit NIST message") {
        const digest = blake2s("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189");
    }

    test("should hash the 896-bit NIST message") {
        const digest = blake2s("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("358dd2ed0780d4054e76cb6f3a5bce2841e8e2f547431d4d09db21b66d941fc7");
    }

    test("should hash runs of a around the block boundary of 64 bytes") {
        let bytes: u8[129] = undefined;
        for (const i of 0..129) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest63 = blake2s(bytes[0..63]);
        const text63: string = try encodeHex(&digest63, &out);
        expect(text63).toBe("9a4267618070af968ff2a0fdaecc62b5c15ab91cb4a56424ba9fcad20aab417c");
        const digest64 = blake2s(bytes[0..64]);
        const text64: string = try encodeHex(&digest64, &out);
        expect(text64).toBe("651d2f5f20952eacaea2fba2f2af2bcd633e511ea2d2e4c9ae2ac0d9ffb7b252");
        const digest65 = blake2s(bytes[0..65]);
        const text65: string = try encodeHex(&digest65, &out);
        expect(text65).toBe("045f8ae18932119bd051ac7ba5c73db59892055fad5c32f82d79a6543d92a497");
        const digest128 = blake2s(bytes[0..128]);
        const text128: string = try encodeHex(&digest128, &out);
        expect(text128).toBe("3ac477e27353f9019b81694afe60c8049403784f91a58288428ea318bfa82809");
        const digest129 = blake2s(bytes[0..129]);
        const text129: string = try encodeHex(&digest129, &out);
        expect(text129).toBe("94f03f8feba7e07dd91153d178bb2d254e8cfd445024a77071f9329200d9517c");
    }
}
