/**
 * Imports
 */

import { encodeHex } from "@hex";
import { Pbkdf2Error, pbkdf2Sha256 } from "@pbkdf2";

/**
 * Tests
 */

describe("pbkdf2Sha256") {
    test("should match the RFC 7914 vector with one iteration and two blocks") {
        let out: u8[64] = undefined;
        const key = try pbkdf2Sha256("passwd", "salt", 1, &out);
        let hex: u8[64] = undefined;
        const head: string = try encodeHex(key[0..32], &hex);
        expect(head).toBe("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
        const tail: string = try encodeHex(key[32..64], &hex);
        expect(tail).toBe("49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");
    }

    test("should match Python for one, two, and 4096 iterations") {
        let out: u8[32] = undefined;
        let hex: u8[64] = undefined;
        const one: string = try encodeHex(try pbkdf2Sha256("password", "salt", 1, &out), &hex);
        expect(one).toBe("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        const two: string = try encodeHex(try pbkdf2Sha256("password", "salt", 2, &out), &hex);
        expect(two).toBe("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
        const many: string = try encodeHex(try pbkdf2Sha256("password", "salt", 4096, &out), &hex);
        expect(many).toBe("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
    }

    test("should cut the last block for an output that isn't a multiple of 32") {
        let out: u8[40] = undefined;
        let hex: u8[80] = undefined;
        const key = try pbkdf2Sha256("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, &out);
        const text: string = try encodeHex(key, &hex);
        expect(text).toBe("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");
    }

    test("should take NUL bytes in the password and the salt") {
        let out: u8[16] = undefined;
        let hex: u8[32] = undefined;
        const text: string = try encodeHex(try pbkdf2Sha256("pass\x00word", "sa\x00lt", 4096, &out), &hex);
        expect(text).toBe("89b69d0516f829893c696226650a8687");
    }

    test("should hash a password longer than the HMAC block") {
        let password: u8[100] = undefined;
        for (const _, i of password) password[i] = 'k';
        let out: u8[33] = undefined;
        let hex: u8[66] = undefined;
        const text: string = try encodeHex(try pbkdf2Sha256(&password, "salt", 3, &out), &hex);
        expect(text).toBe("219c68bb88f1010f4a763b7c8fd58639c2280baf6820814c6d404891fcd85c3d19");
    }

    test("should write nothing for an empty buffer") {
        let out: u8[1] = undefined;
        expect((try pbkdf2Sha256("password", "salt", 1, out[0..0])).len).toBe(0);
    }

    test("should reject zero iterations") {
        let out: u8[32] = undefined;
        expect(pbkdf2Sha256("password", "salt", 0, &out)).toThrow(Pbkdf2Error.ZeroIterations);
    }
}
