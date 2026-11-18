/**
 * Imports
 */

import { encodeHex } from "@hex";
import { Keccak } from "@sha3/structs/keccak.struct";

/**
 * Tests
 */

describe("Keccak") {
    test("should start with a zero state and the given parameters") {
        const sponge = Keccak.init(136, 0x06);
        for (const lane of sponge.state) expect(lane).toBe(0);
        expect(sponge.rate).toBe(136);
        expect(sponge.used).toBe(0);
        expect(sponge.suffix).toBe(0x06);
    }

    test("should permute each time a full rate is absorbed") {
        let bytes: u8[137] = undefined;
        for (const i of 0..137) bytes[i] = 'a';
        let sponge = Keccak.init(136, 0x06);
        sponge.absorb(bytes[0..135]);
        expect(sponge.used).toBe(135);
        sponge.absorb(bytes[135..136]);
        expect(sponge.used).toBe(0);
        sponge.absorb(bytes[136..137]);
        expect(sponge.used).toBe(1);
    }

    test("should give SHA3-256 with a rate of 136 and the suffix 0x06") {
        let sponge = Keccak.init(136, 0x06);
        sponge.absorb("abc");
        sponge.pad();
        let digest: u8[32] = undefined;
        sponge.squeeze(&digest);
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    }

    test("should put the suffix and the final bit on one byte when only one byte of the rate is left") {
        let bytes: u8[135] = undefined;
        for (const i of 0..135) bytes[i] = 'a';
        let sponge = Keccak.init(136, 0x06);
        sponge.absorb(&bytes);
        sponge.pad();
        let digest: u8[32] = undefined;
        sponge.squeeze(&digest);
        let out: u8[64] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9");
    }

    test("should squeeze the same stream in pieces as in one call") {
        let sponge = Keccak.init(168, 0x1F);
        sponge.pad();
        let digest: u8[200] = undefined;
        sponge.squeeze(digest[0..7]);
        sponge.squeeze(digest[7..200]);
        let out: u8[400] = undefined;
        const text: string = try encodeHex(&digest, &out);
        expect(text).toBe("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f877");
    }
}
