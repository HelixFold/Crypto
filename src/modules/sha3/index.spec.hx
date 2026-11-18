/**
 * Imports
 */

import { encodeHex } from "@hex";
import { sha3x224, sha3x256, sha3x384, sha3x512, shake128, shake256 } from "@sha3";

/**
 * Tests
 */

describe("sha3x224") {
    test("should hash the empty message") {
        const digest = sha3x224("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    }

    test("should hash the message abc") {
        const digest = sha3x224("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    }

    test("should hash the 448-bit NIST message") {
        const digest = sha3x224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33");
    }

    test("should hash the 896-bit NIST message") {
        const digest = sha3x224("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc");
    }

    test("should hash runs of a around the rate of 144 bytes") {
        let bytes: u8[145] = undefined;
        for (const i of 0..145) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest143 = sha3x224(bytes[0..143]);
        const text143: string = try encodeHex(&digest143, &out);
        expect(text143).toBe("73b1b22b54f515f626a6abdde6af25cd4801dc6e9dc7fa3f77e1c122");
        const digest144 = sha3x224(bytes[0..144]);
        const text144: string = try encodeHex(&digest144, &out);
        expect(text144).toBe("f9019111996dcf160e284e320fd6d8825cabcd41a5ffdc4c5e9d64b6");
        const digest145 = sha3x224(bytes[0..145]);
        const text145: string = try encodeHex(&digest145, &out);
        expect(text145).toBe("7f0521c84aeacc8a46aba17171acbdd22522509a71c663257fbdee0e");
    }
}

describe("sha3x256") {
    test("should hash the empty message") {
        const digest = sha3x256("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }

    test("should hash the message abc") {
        const digest = sha3x256("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    }

    test("should hash the 448-bit NIST message") {
        const digest = sha3x256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
    }

    test("should hash the 896-bit NIST message") {
        const digest = sha3x256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");
    }

    test("should hash runs of a around the rate of 136 bytes") {
        let bytes: u8[137] = undefined;
        for (const i of 0..137) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest135 = sha3x256(bytes[0..135]);
        const text135: string = try encodeHex(&digest135, &out);
        expect(text135).toBe("8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9");
        const digest136 = sha3x256(bytes[0..136]);
        const text136: string = try encodeHex(&digest136, &out);
        expect(text136).toBe("3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1");
        const digest137 = sha3x256(bytes[0..137]);
        const text137: string = try encodeHex(&digest137, &out);
        expect(text137).toBe("f8d6846cedd2ccfadf15c5879ef95af724d799eed7391fb1c91f95344e738614");
    }
}

describe("sha3x384") {
    test("should hash the empty message") {
        const digest = sha3x384("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    }

    test("should hash the message abc") {
        const digest = sha3x384("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
    }

    test("should hash the 448-bit NIST message") {
        const digest = sha3x384("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22");
    }

    test("should hash the 896-bit NIST message") {
        const digest = sha3x384("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7");
    }

    test("should hash runs of a around the rate of 104 bytes") {
        let bytes: u8[105] = undefined;
        for (const i of 0..105) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest103 = sha3x384(bytes[0..103]);
        const text103: string = try encodeHex(&digest103, &out);
        expect(text103).toBe("af61fb4fd1c6afe80857fcba888318a0a1426635b4509f09707e3787630bdb621655ffa54f5884088ccc000f81436414");
        const digest104 = sha3x384(bytes[0..104]);
        const text104: string = try encodeHex(&digest104, &out);
        expect(text104).toBe("3a4f3b6284e571238884e95655e8c8a60e068e4059a9734abc08823a900d161592860243f00619ae699a29092ed91a16");
        const digest105 = sha3x384(bytes[0..105]);
        const text105: string = try encodeHex(&digest105, &out);
        expect(text105).toBe("cb73ab2f8f5fbb13f0e115a7062ba1644aa16534aa80d076ef27f8550deb900d89bdfa169b45073223acadb6001204d3");
    }
}

describe("sha3x512") {
    test("should hash the empty message") {
        const digest = sha3x512("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    }

    test("should hash the message abc") {
        const digest = sha3x512("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
    }

    test("should hash the 448-bit NIST message") {
        const digest = sha3x512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e");
    }

    test("should hash the 896-bit NIST message") {
        const digest = sha3x512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185");
    }

    test("should hash runs of a around the rate of 72 bytes") {
        let bytes: u8[73] = undefined;
        for (const i of 0..73) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest71 = sha3x512(bytes[0..71]);
        const text71: string = try encodeHex(&digest71, &out);
        expect(text71).toBe("070faf98d2a8fddf8ed886408744dc06456096c2e045f26f3c7b010530e6bbb3db535a54d636856f4e0e1e982461cb9a7e8e57ff8895cff1619af9f0e486e28c");
        const digest72 = sha3x512(bytes[0..72]);
        const text72: string = try encodeHex(&digest72, &out);
        expect(text72).toBe("a8ae722a78e10cbbc413886c02eb5b369a03f6560084aff566bd597bb7ad8c1ccd86e81296852359bf2faddb5153c0a7445722987875e74287adac21adebe952");
        const digest73 = sha3x512(bytes[0..73]);
        const text73: string = try encodeHex(&digest73, &out);
        expect(text73).toBe("23e6a8815f8201dbbf6a5463be8dcadb1acea9df5f8998954e59ac9565cf6d29b17aa27a5e8b0fc06343db6122d6e544d27583ddc78504d08203217e7e65b6bd");
    }
}

describe("shake128") {
    test("should give 32 bytes of the empty message") {
        let digest: u8[32] = undefined;
        shake128("", &digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    }

    test("should give 32 bytes of the message abc") {
        let digest: u8[32] = undefined;
        shake128("abc", &digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
    }

    test("should give 32 bytes of the 448-bit NIST message") {
        let digest: u8[32] = undefined;
        shake128("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", &digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f5");
    }

    test("should give 64 bytes of the empty message that start with its 32 bytes") {
        let digest: u8[64] = undefined;
        shake128("", &digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2");
    }

    test("should give an output longer than several rates") {
        let digest: u8[300] = undefined;
        shake128("abc", &digest);
        let out: u8[600] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49acc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd4818cb006aa5b4cdb3611eb1e533c8964cacfdf31012cd3fb744d02225b988b475375faad996eb1b9176ecb0f8b2871723d6dbb804e23357e50732f5cfc904b1319795000d7361d9e5e1b77b4b8f5774aa1482cfa58f83096bdb2e06a3eed543a38919b57ecbec737f4086be");
    }

    test("should absorb runs of a around the rate of 168 bytes") {
        let bytes: u8[169] = undefined;
        for (const i of 0..169) bytes[i] = 'a';
        let out: u8[128] = undefined;
        let digest167: u8[32] = undefined;
        shake128(bytes[0..167], &digest167);
        const text167: string = try encodeHex(&digest167, &out);
        expect(text167).toBe("4f5c6c53ae8190a8ff8a55b2125d28703052d10278570960c2066a905d916c34");
        let digest168: u8[32] = undefined;
        shake128(bytes[0..168], &digest168);
        const text168: string = try encodeHex(&digest168, &out);
        expect(text168).toBe("c22e11586c22b713bde373fce93314d76829de2c21d940a28eb659b8dec953a2");
        let digest169: u8[32] = undefined;
        shake128(bytes[0..169], &digest169);
        const text169: string = try encodeHex(&digest169, &out);
        expect(text169).toBe("09fc23f3acfd944380db0c7f5b1bde62d3a43c6e4c61ca9cb3dfee54904b36a8");
    }

    test("should leave an empty buffer alone") {
        let digest: u8[1] = [0x55];
        shake128("abc", digest[0..0]);
        expect(digest[0]).toBe(0x55);
    }
}

describe("shake256") {
    test("should give 32 bytes of the empty message") {
        let digest: u8[32] = undefined;
        shake256("", &digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    }

    test("should give 32 bytes of the message abc") {
        let digest: u8[32] = undefined;
        shake256("abc", &digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
    }

    test("should give 32 bytes of the 448-bit NIST message") {
        let digest: u8[32] = undefined;
        shake256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", &digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e3329");
    }

    test("should give 64 bytes of the empty message that start with its 32 bytes") {
        let digest: u8[64] = undefined;
        shake256("", &digest);
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
    }

    test("should give an output longer than several rates") {
        let digest: u8[300] = undefined;
        shake256("abc", &digest);
        let out: u8[600] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b33a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b677513771af6bfe11934817e8762d9896ba579d88d84ba7aa3cdc7055f6796f195bd9ae788f2f5bb96100d6bbaff7fbc6eea24d4449a2477d172a5507dcc931412fc346b1bb39b878330e026b12ddf384af3334560ea1d363966caa7d8ddcbec7da52b42215c11d5f8ee57f341");
    }

    test("should absorb runs of a around the rate of 136 bytes") {
        let bytes: u8[137] = undefined;
        for (const i of 0..137) bytes[i] = 'a';
        let out: u8[128] = undefined;
        let digest135: u8[32] = undefined;
        shake256(bytes[0..135], &digest135);
        const text135: string = try encodeHex(&digest135, &out);
        expect(text135).toBe("55b991ece1e567b6e7c2c714444dd201cd51f4f3832d08e1d26bebc63e07a3d7");
        let digest136: u8[32] = undefined;
        shake256(bytes[0..136], &digest136);
        const text136: string = try encodeHex(&digest136, &out);
        expect(text136).toBe("8fcc5a08f0a1f6827c9cf64ee8d16e0443106359ca6c8efd230759256f44996a");
        let digest137: u8[32] = undefined;
        shake256(bytes[0..137], &digest137);
        const text137: string = try encodeHex(&digest137, &out);
        expect(text137).toBe("a44e1a438dad6273d540be65ee26386c59588efb09139dc086385d2db0c25782");
    }

    test("should leave an empty buffer alone") {
        let digest: u8[1] = [0x55];
        shake256("abc", digest[0..0]);
        expect(digest[0]).toBe(0x55);
    }
}
