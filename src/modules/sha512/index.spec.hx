/**
 * Imports
 */

import { encodeHex } from "@hex";
import { sha384, sha512 } from "@sha512";

/**
 * Tests
 */

describe("sha512") {
    test("should hash the empty message") {
        const digest = sha512("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    test("should hash the message abc") {
        const digest = sha512("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }

    test("should hash the 448-bit NIST message") {
        const digest = sha512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
    }

    test("should hash the 896-bit NIST message") {
        const digest = sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    }

    test("should hash runs of a around the block boundary of 128 bytes") {
        let bytes: u8[129] = undefined;
        for (const i of 0..129) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest111 = sha512(bytes[0..111]);
        const text111: string = try encodeHex(&digest111, &out);
        expect(text111).toBe("fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2");
        const digest112 = sha512(bytes[0..112]);
        const text112: string = try encodeHex(&digest112, &out);
        expect(text112).toBe("c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca");
        const digest127 = sha512(bytes[0..127]);
        const text127: string = try encodeHex(&digest127, &out);
        expect(text127).toBe("828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502");
        const digest128 = sha512(bytes[0..128]);
        const text128: string = try encodeHex(&digest128, &out);
        expect(text128).toBe("b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321");
        const digest129 = sha512(bytes[0..129]);
        const text129: string = try encodeHex(&digest129, &out);
        expect(text129).toBe("4f681e0bd53cda4b5a2041cc8a06f2eabde44fb16c951fbd5b87702f07aeab611565b19c47fde30587177ebb852e3971bbd8d3fd30da18d71037dfbd98420429");
    }
}

describe("sha384") {
    test("should hash the empty message") {
        const digest = sha384("");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    }

    test("should hash the message abc") {
        const digest = sha384("abc");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    }

    test("should hash the 448-bit NIST message") {
        const digest = sha384("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
    }

    test("should hash the 896-bit NIST message") {
        const digest = sha384("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
    }

    test("should hash runs of a around the block boundary of 128 bytes") {
        let bytes: u8[129] = undefined;
        for (const i of 0..129) bytes[i] = 'a';
        let out: u8[128] = undefined;
        const digest111 = sha384(bytes[0..111]);
        const text111: string = try encodeHex(&digest111, &out);
        expect(text111).toBe("3c37955051cb5c3026f94d551d5b5e2ac38d572ae4e07172085fed81f8466b8f90dc23a8ffcdea0b8d8e58e8fdacc80a");
        const digest112 = sha384(bytes[0..112]);
        const text112: string = try encodeHex(&digest112, &out);
        expect(text112).toBe("187d4e07cb306103c69967bf544d0dfbe9042577599c73c330abc0cb64c61236d5ed565ee19119d8c31779a38f791fcd");
        const digest127 = sha384(bytes[0..127]);
        const text127: string = try encodeHex(&digest127, &out);
        expect(text127).toBe("9bd06b1763c2cf7aef40e795dc65bc96d59c41b537f3ad72ebdefd485476b5717c1aeb37c327fe9c1831b12b9efd08ae");
        const digest128 = sha384(bytes[0..128]);
        const text128: string = try encodeHex(&digest128, &out);
        expect(text128).toBe("edb12730a366098b3b2beac75a3bef1b0969b15c48e2163c23d96994f8d1bef760c7e27f3c464d3829f56c0d53808b0b");
        const digest129 = sha384(bytes[0..129]);
        const text129: string = try encodeHex(&digest129, &out);
        expect(text129).toBe("39b6f5a7b0e781dbc419f72e49b30eaac10f2c98c4403bc610da31067fd1b48f324138c8615d2b496d08d73d5e865326");
    }
}
