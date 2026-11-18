/**
 * Imports
 */

import { encodeHex } from "@hex";
import { ScryptError, scrypt } from "@scrypt";

/**
 * Tests
 */

describe("scrypt") {
    test("should match RFC 7914 test vector 1") {
        let out: u8[64] = undefined;
        const key = try scrypt(testing.allocator, "", "", 16, 1, 1, &out);
        let hex: u8[64] = undefined;
        const head: string = try encodeHex(key[0..32], &hex);
        expect(head).toBe("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442");
        const tail: string = try encodeHex(key[32..64], &hex);
        expect(tail).toBe("fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
    }

    test("should match RFC 7914 test vector 2") {
        let out: u8[64] = undefined;
        const key = try scrypt(testing.allocator, "password", "NaCl", 1024, 8, 16, &out);
        let hex: u8[64] = undefined;
        const head: string = try encodeHex(key[0..32], &hex);
        expect(head).toBe("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162");
        const tail: string = try encodeHex(key[32..64], &hex);
        expect(tail).toBe("2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
    }

    test("should take the smallest cost") {
        let out: u8[32] = undefined;
        let hex: u8[64] = undefined;
        const text: string = try encodeHex(try scrypt(testing.allocator, "pw", "salt", 2, 1, 1, &out), &hex);
        expect(text).toBe("a22ef056777184a8f40be275b0749299418e34463e09cfa1553dc200c17c06df");
    }

    test("should mix several lanes with a block size above 1") {
        let out: u8[48] = undefined;
        const key = try scrypt(testing.allocator, "pw", "salt", 16, 2, 3, &out);
        let hex: u8[48] = undefined;
        const head: string = try encodeHex(key[0..24], &hex);
        expect(head).toBe("1d7de095e073b06f2939e344605a92fd7836e9e4fa69e645");
        const tail: string = try encodeHex(key[24..48], &hex);
        expect(tail).toBe("b791e8bec33f99930b9335ab0330894fb5134401f9ac6f3c");
    }

    test("should reject a cost that is not a power of two greater than 1") {
        let out: u8[32] = undefined;
        expect(scrypt(testing.allocator, "pw", "salt", 0, 1, 1, &out)).toThrow(ScryptError.BadCost);
        expect(scrypt(testing.allocator, "pw", "salt", 1, 1, 1, &out)).toThrow(ScryptError.BadCost);
        expect(scrypt(testing.allocator, "pw", "salt", 1000, 1, 1, &out)).toThrow(ScryptError.BadCost);
    }

    test("should reject a cost of 2^(16 r) or more") {
        let out: u8[32] = undefined;
        expect(scrypt(testing.allocator, "pw", "salt", 65536, 1, 1, &out)).toThrow(ScryptError.BadCost);
        expect(scrypt(testing.allocator, "pw", "salt", 1 << 32, 2, 1, &out)).toThrow(ScryptError.BadCost);
    }

    test("should reject a block size of zero") {
        let out: u8[32] = undefined;
        expect(scrypt(testing.allocator, "pw", "salt", 16, 0, 1, &out)).toThrow(ScryptError.BadBlockSize);
    }

    test("should reject a parallelism of zero or a product with r of 2^30") {
        let out: u8[32] = undefined;
        expect(scrypt(testing.allocator, "pw", "salt", 16, 1, 0, &out)).toThrow(ScryptError.BadParallelism);
        expect(scrypt(testing.allocator, "pw", "salt", 16, 1 << 15, 1 << 15, &out)).toThrow(ScryptError.BadParallelism);
    }

    test("should reject parameters whose memory doesn't fit in a usize") {
        let out: u8[32] = undefined;
        expect(scrypt(testing.allocator, "pw", "salt", 1 << 62, 1 << 20, 1, &out)).toThrow(ScryptError.TooMuchMemory);
    }

    test("should write nothing for an empty buffer") {
        let out: u8[1] = undefined;
        expect((try scrypt(testing.allocator, "pw", "salt", 4, 1, 1, out[0..0])).len).toBe(0);
    }
}
