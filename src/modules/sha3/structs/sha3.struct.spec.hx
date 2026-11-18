/**
 * Imports
 */

import { encodeHex } from "@hex";
import { Sha3x224, Sha3x256, Sha3x384, Sha3x512, Shake128, Shake256 } from "@sha3/structs/sha3.struct";

/**
 * Tests
 */

describe("Sha3x224") {
    test("should finish to the digest of no bytes") {
        const hash = Sha3x224.init();
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    }

    test("should give the same digest wherever the 448-bit message is split") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Sha3x224.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            const digest = hash.finish();
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha3x224.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc");
    }

    test("should keep the state when finishing") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Sha3x224.init();
        hash.update(message[0..32]);
        const early = hash.finish();
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("b31cd8140847c466a61e1c249d81c0a421daf3695361e6b905157e3e");
        hash.update(message[32..message.len]);
        const digest = hash.finish();
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Sha3x224.init();
        for (const _ of 0..1000) hash.update(&chunk);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c");
    }

    test("should start an empty sponge at the rate of SHA3-224") {
        let hash = Sha3x224.init();
        expect(hash.sponge.rate).toBe(144);
        expect(hash.sponge.suffix).toBe(0x06);
        hash.update("abc");
        expect(hash.sponge.used).toBe(3);
    }
}

describe("Sha3x256") {
    test("should finish to the digest of no bytes") {
        const hash = Sha3x256.init();
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }

    test("should give the same digest wherever the 448-bit message is split") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Sha3x256.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            const digest = hash.finish();
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha3x256.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");
    }

    test("should keep the state when finishing") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Sha3x256.init();
        hash.update(message[0..32]);
        const early = hash.finish();
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("b04cd1b18e04c94a436804c2048f168c129402e198235b9ae2f26dc91267c02d");
        hash.update(message[32..message.len]);
        const digest = hash.finish();
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Sha3x256.init();
        for (const _ of 0..1000) hash.update(&chunk);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1");
    }

    test("should start an empty sponge at the rate of SHA3-256") {
        let hash = Sha3x256.init();
        expect(hash.sponge.rate).toBe(136);
        expect(hash.sponge.suffix).toBe(0x06);
        hash.update("abc");
        expect(hash.sponge.used).toBe(3);
    }
}

describe("Sha3x384") {
    test("should finish to the digest of no bytes") {
        const hash = Sha3x384.init();
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    }

    test("should give the same digest wherever the 896-bit message is split") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Sha3x384.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            const digest = hash.finish();
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha3x384.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7");
    }

    test("should keep the state when finishing") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha3x384.init();
        hash.update(message[0..32]);
        const early = hash.finish();
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("2e1fff80d3d3dfd1bf43bd6fc23fb5332eed10cd654adcb07cc8ab3b7c2008962712f42b1eaec54c250119932059ccfe");
        hash.update(message[32..message.len]);
        const digest = hash.finish();
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Sha3x384.init();
        for (const _ of 0..1000) hash.update(&chunk);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340");
    }

    test("should start an empty sponge at the rate of SHA3-384") {
        let hash = Sha3x384.init();
        expect(hash.sponge.rate).toBe(104);
        expect(hash.sponge.suffix).toBe(0x06);
        hash.update("abc");
        expect(hash.sponge.used).toBe(3);
    }
}

describe("Sha3x512") {
    test("should finish to the digest of no bytes") {
        const hash = Sha3x512.init();
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    }

    test("should give the same digest wherever the 896-bit message is split") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Sha3x512.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            const digest = hash.finish();
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha3x512.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185");
    }

    test("should keep the state when finishing") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha3x512.init();
        hash.update(message[0..32]);
        const early = hash.finish();
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("2ed86e9d45e98915ae89e32e50bf61a315b0e9252fa34317fe5da96dc7023a7aeaddc6e43c5331c1e005532955a5fb331bf3e1489f1b4d0a78e1175c96e5af4f");
        hash.update(message[32..message.len]);
        const digest = hash.finish();
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Sha3x512.init();
        for (const _ of 0..1000) hash.update(&chunk);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87");
    }

    test("should start an empty sponge at the rate of SHA3-512") {
        let hash = Sha3x512.init();
        expect(hash.sponge.rate).toBe(72);
        expect(hash.sponge.suffix).toBe(0x06);
        hash.update("abc");
        expect(hash.sponge.used).toBe(3);
    }
}

describe("Shake128") {
    test("should finish to the digest of no bytes") {
        const hash = Shake128.init();
        let digestReader = hash.finish();
        let digest: u8[32] = undefined;
        digestReader.squeeze(&digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    }

    test("should give the same digest wherever the 448-bit message is split") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Shake128.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            let digestReader = hash.finish();
            let digest: u8[32] = undefined;
            digestReader.squeeze(&digest);
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f5");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Shake128.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        let digestReader = hash.finish();
        let digest: u8[32] = undefined;
        digestReader.squeeze(&digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("7b6df6ff181173b6d7898d7ff63fb07b7c237daf471a5ae5602adbccef9ccf4b");
    }

    test("should keep the state when finishing") {
        const message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = Shake128.init();
        hash.update(message[0..32]);
        let earlyReader = hash.finish();
        let early: u8[32] = undefined;
        earlyReader.squeeze(&early);
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("cfed478f126f2b25fd98bd02b1e4c75e4ebd6743974beefe4fdec69abee580a7");
        hash.update(message[32..message.len]);
        let digestReader = hash.finish();
        let digest: u8[32] = undefined;
        digestReader.squeeze(&digest);
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f5");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Shake128.init();
        for (const _ of 0..1000) hash.update(&chunk);
        let digestReader = hash.finish();
        let digest: u8[32] = undefined;
        digestReader.squeeze(&digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58");
    }

    test("should continue the output across calls and permutations") {
        let hash = Shake128.init();
        hash.update("abc");
        let reader = hash.finish();
        let digest: u8[400] = undefined;
        reader.squeeze(digest[0..1]);
        reader.squeeze(digest[1..168]);
        reader.squeeze(digest[168..169]);
        reader.squeeze(digest[169..336]);
        reader.squeeze(digest[336..400]);
        let out: u8[800] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49acc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd4818cb006aa5b4cdb3611eb1e533c8964cacfdf31012cd3fb744d02225b988b475375faad996eb1b9176ecb0f8b2871723d6dbb804e23357e50732f5cfc904b1319795000d7361d9e5e1b77b4b8f5774aa1482cfa58f83096bdb2e06a3eed543a38919b57ecbec737f4086be007f8ef80094ceea8807193d46e9be540b6e99b4c1c71507095028a024e8d39aa8f4c5854cedd50d30a223e7d54e9a24f0a2526b31002afbd1b4ebea69c8400c3deb4c1c35d6dbb75651b284076f5fde47b4a0586ee173e30bd4d08f2bc59c6114bdd745");
    }

    test("should give the same stream from two readers of one hash") {
        let hash = Shake128.init();
        hash.update("abc");
        let first = hash.finish();
        let second = hash.finish();
        let a: u8[176] = undefined;
        let b: u8[176] = undefined;
        first.squeeze(&a);
        second.squeeze(b[0..8]);
        second.squeeze(b[8..176]);
        let outA: u8[352] = undefined;
        let outB: u8[352] = undefined;
        const textA: string = try encodeHex(&a, &outA);
        const textB: string = try encodeHex(&b, &outB);
        expect(textA).toBe(textB);
        expect(textA).toBe("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49acc29082f5647584e6aa01b3f5af05780");
    }
}

describe("Shake256") {
    test("should finish to the digest of no bytes") {
        const hash = Shake256.init();
        let digestReader = hash.finish();
        let digest: u8[32] = undefined;
        digestReader.squeeze(&digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    }

    test("should give the same digest wherever the 896-bit message is split") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Shake256.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            let digestReader = hash.finish();
            let digest: u8[32] = undefined;
            digestReader.squeeze(&digest);
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf45");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Shake256.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        let digestReader = hash.finish();
        let digest: u8[32] = undefined;
        digestReader.squeeze(&digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf45");
    }

    test("should keep the state when finishing") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Shake256.init();
        hash.update(message[0..32]);
        let earlyReader = hash.finish();
        let early: u8[32] = undefined;
        earlyReader.squeeze(&early);
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("2765584e5047f1aba6980c9a20887dbc5c0951acf0ce10f9f5f9a80845e43d7e");
        hash.update(message[32..message.len]);
        let digestReader = hash.finish();
        let digest: u8[32] = undefined;
        digestReader.squeeze(&digest);
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf45");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Shake256.init();
        for (const _ of 0..1000) hash.update(&chunk);
        let digestReader = hash.finish();
        let digest: u8[32] = undefined;
        digestReader.squeeze(&digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a");
    }

    test("should continue the output across calls and permutations") {
        let hash = Shake256.init();
        hash.update("abc");
        let reader = hash.finish();
        let digest: u8[400] = undefined;
        reader.squeeze(digest[0..1]);
        reader.squeeze(digest[1..136]);
        reader.squeeze(digest[136..137]);
        reader.squeeze(digest[137..272]);
        reader.squeeze(digest[272..400]);
        let out: u8[800] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b33a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b677513771af6bfe11934817e8762d9896ba579d88d84ba7aa3cdc7055f6796f195bd9ae788f2f5bb96100d6bbaff7fbc6eea24d4449a2477d172a5507dcc931412fc346b1bb39b878330e026b12ddf384af3334560ea1d363966caa7d8ddcbec7da52b42215c11d5f8ee57f341e399343ce63a752fc5edec99124a0eb314403e5f358b8b83d05be2d2970099284b00dcc33d7c753d1f752ab743325bc53d91aa671e50f9c3f93abf6e9662f90145c61954f2abbd26edad1553ea3a626f359e8f79ade16384e151755c47e822fc74c5d710");
    }

    test("should give the same stream from two readers of one hash") {
        let hash = Shake256.init();
        hash.update("abc");
        let first = hash.finish();
        let second = hash.finish();
        let a: u8[144] = undefined;
        let b: u8[144] = undefined;
        first.squeeze(&a);
        second.squeeze(b[0..8]);
        second.squeeze(b[8..144]);
        let outA: u8[288] = undefined;
        let outB: u8[288] = undefined;
        const textA: string = try encodeHex(&a, &outA);
        const textB: string = try encodeHex(&b, &outB);
        expect(textA).toBe(textB);
        expect(textA).toBe("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e8a2d7ec71a7cc29cf0ea610eeff1a58");
    }
}
