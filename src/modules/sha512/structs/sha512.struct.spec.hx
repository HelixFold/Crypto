/**
 * Imports
 */

import { encodeHex } from "@hex";
import { Sha384, Sha512 } from "@sha512/structs/sha512.struct";

/**
 * Tests
 */

describe("Sha512") {
    test("should finish to the digest of no bytes") {
        const hash = Sha512.init();
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    test("should give the same digest wherever the 896-bit message is split") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Sha512.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            const digest = hash.finish();
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha512.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    }

    test("should keep the state when finishing") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha512.init();
        hash.update(message[0..32]);
        const early = hash.finish();
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("9a20891c188e27f40f1a2093cb3a7c3479e6435351fd3031a8f36dbb3c644fddf6f8ae7a549d073276fd982a77602fbfaf6175325323d492dec3a9cff23b42c3");
        hash.update(message[32..message.len]);
        const digest = hash.finish();
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Sha512.init();
        for (const _ of 0..1000) hash.update(&chunk);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
    }

    test("should count the bytes and keep a partial block waiting") {
        let hash = Sha512.init();
        expect(hash.state[0]).toBe(0x6a09e667f3bcc908);
        hash.update("abc");
        expect(hash.length).toBe(3);
        expect(hash.used).toBe(3);
        expect(hash.block[0]).toBe('a');
    }
}

describe("Sha384") {
    test("should finish to the digest of no bytes") {
        const hash = Sha384.init();
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    }

    test("should give the same digest wherever the 896-bit message is split") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let out: u8[128] = undefined;
        for (const i of 0..message.len + 1) {
            let hash = Sha384.init();
            hash.update(message[0..i]);
            hash.update(message[i..message.len]);
            const digest = hash.finish();
            const text: string = try encodeHex(&digest, &out);
            expect(text).toBe("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
        }
    }

    test("should give the same digest when fed one byte at a time") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha384.init();
        for (const i of 0..message.len) hash.update(message[i..i + 1]);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
    }

    test("should keep the state when finishing") {
        const message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let hash = Sha384.init();
        hash.update(message[0..32]);
        const early = hash.finish();
        let out: u8[128] = undefined;
        const earlyText: string = try encodeHex(&early, &out);
        expect(earlyText).toBe("34d9596f1c249e10eda5527cb55cb9c6d5d8099a49915dee54c7c8cdfab37f93c26109386c6383dbc09701974b90d849");
        hash.update(message[32..message.len]);
        const digest = hash.finish();
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
    }

    test("should hash a million a's") {
        let chunk: u8[1000] = undefined;
        for (const i of 0..1000) chunk[i] = 'a';
        let hash = Sha384.init();
        for (const _ of 0..1000) hash.update(&chunk);
        const digest = hash.finish();
        let out: u8[128] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985");
    }
}
