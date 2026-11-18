/**
 * Imports
 */

import { decodeHex, encodeHex } from "@hex";
import { Poly1305, Poly1305Error, poly1305 } from "@poly1305";

/**
 * Computes the Poly1305 tag of hex inputs and writes it as hex.
 *
 * @param keyHex - The 32-byte key, as 64 hex digits
 * @param rows - The message, as rows of up to 64 hex digits
 * @param digits - The buffer for the 32 digits of the tag
 * @returns The part of `digits` that holds the tag
 *
 * @remarks
 * It lets each vector of RFC 8439, appendix A.3, read as its key, its message, and its tag.
 * The message may be up to 64 bytes long.
 *
 * @since 1.0.0
 */

function tagOf(keyHex: readonly u8[], rows: readonly string[], digits: u8[]): u8[] | Error {
    let key: u8[32] = undefined;
    void try decodeHex(keyHex, &key);
    let message: u8[64] = undefined;
    let at: usize = 0;
    for (const row of rows) {
        const bytes = try decodeHex(row, message[at..]);
        at += bytes.len;
    }
    const tag = try poly1305(&key, message[0..at]);
    return try encodeHex(&tag, digits);
}

/**
 * Tests
 */

describe("poly1305") {
    test("should match the tag of RFC 8439, section 2.5.2") {
        let key: u8[32] = undefined;
        void try decodeHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", &key);
        const tag = try poly1305(&key, "Cryptographic Forum Research Group");
        let digits: u8[32] = undefined;
        const text: string = try encodeHex(&tag, &digits);
        expect(text).toBe("a8061dc1305136c6c22b8baf0c0127a9");
    }

    test("should give s as the tag of an empty message") {
        let key: u8[32] = undefined;
        void try decodeHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", &key);
        const tag = try poly1305(&key, "");
        let digits: u8[32] = undefined;
        const text: string = try encodeHex(&tag, &digits);
        expect(text).toBe("0103808afb0db2fd4abff6af4149f51b");
    }

    test("should give a zero tag for the zero key, as in RFC 8439, appendix A.3, vector 1") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = 0;
        let message: u8[64] = undefined;
        for (const _, i of message) message[i] = 0;
        const tag = try poly1305(&key, &message);
        let digits: u8[32] = undefined;
        const text: string = try encodeHex(&tag, &digits);
        expect(text).toBe("00000000000000000000000000000000");
    }

    test("should wrap h modulo 2 to the 128, as in appendix A.3, vector 5") {
        const key = "0200000000000000000000000000000000000000000000000000000000000000";
        const rows: string[1] = ["ffffffffffffffffffffffffffffffff"];
        let digits: u8[32] = undefined;
        const text: string = try tagOf(key, &rows, &digits);
        expect(text).toBe("03000000000000000000000000000000");
    }

    test("should wrap h plus s modulo 2 to the 128, as in appendix A.3, vector 6") {
        const key = "02000000000000000000000000000000ffffffffffffffffffffffffffffffff";
        const rows: string[1] = ["02000000000000000000000000000000"];
        let digits: u8[32] = undefined;
        const text: string = try tagOf(key, &rows, &digits);
        expect(text).toBe("03000000000000000000000000000000");
    }

    test("should reduce h when it is p or just above, as in appendix A.3, vector 7") {
        const key = "0100000000000000000000000000000000000000000000000000000000000000";
        const rows: string[2] = [
            "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff",
            "11000000000000000000000000000000",
        ];
        let digits: u8[32] = undefined;
        const text: string = try tagOf(key, &rows, &digits);
        expect(text).toBe("05000000000000000000000000000000");
    }

    test("should reduce h to zero, as in appendix A.3, vector 8") {
        const key = "0100000000000000000000000000000000000000000000000000000000000000";
        const rows: string[2] = [
            "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe",
            "01010101010101010101010101010101",
        ];
        let digits: u8[32] = undefined;
        const text: string = try tagOf(key, &rows, &digits);
        expect(text).toBe("00000000000000000000000000000000");
    }

    test("should leave h below p alone, as in appendix A.3, vector 9") {
        const key = "0200000000000000000000000000000000000000000000000000000000000000";
        const rows: string[1] = ["fdffffffffffffffffffffffffffffff"];
        let digits: u8[32] = undefined;
        const text: string = try tagOf(key, &rows, &digits);
        expect(text).toBe("faffffffffffffffffffffffffffffff");
    }

    test("should carry across the limbs, as in appendix A.3, vectors 10 and 11") {
        const key = "0100000000000000040000000000000000000000000000000000000000000000";
        const four: string[2] = [
            "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000",
            "0000000000000000000000000000000001000000000000000000000000000000",
        ];
        let digits: u8[32] = undefined;
        const ten: string = try tagOf(key, &four, &digits);
        expect(ten).toBe("14000000000000005500000000000000");

        const three: string[2] = [
            "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000",
            "00000000000000000000000000000000",
        ];
        let moreDigits: u8[32] = undefined;
        const eleven: string = try tagOf(key, &three, &moreDigits);
        expect(eleven).toBe("13000000000000000000000000000000");
    }

    test("should reject a key that is not 32 bytes") {
        let key: u8[33] = undefined;
        for (const _, i of key) key[i] = 0;
        expect(poly1305(key[0..31], "abc")).toThrow(Poly1305Error.BadKeyLength);
        expect(poly1305(&key, "abc")).toThrow(Poly1305Error.BadKeyLength);
        expect(poly1305("", "abc")).toThrow(Poly1305Error.BadKeyLength);
    }
}

describe("Poly1305") {
    test("should give the same tag wherever the message is split") {
        let key: u8[32] = undefined;
        void try decodeHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", &key);
        const message = "Cryptographic Forum Research Group";
        for (const i of 0..message.len + 1) {
            let mac = try Poly1305.init(&key);
            mac.update(message[0..i]);
            mac.update(message[i..message.len]);
            const tag = mac.finish();
            let digits: u8[32] = undefined;
            const text: string = try encodeHex(&tag, &digits);
            expect(text).toBe("a8061dc1305136c6c22b8baf0c0127a9");
        }
    }

    test("should give the same tag when fed one byte at a time") {
        let key: u8[32] = undefined;
        void try decodeHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", &key);
        const message = "Cryptographic Forum Research Group";
        let mac = try Poly1305.init(&key);
        for (const i of 0..message.len) mac.update(message[i..i + 1]);
        const tag = mac.finish();
        let digits: u8[32] = undefined;
        const text: string = try encodeHex(&tag, &digits);
        expect(text).toBe("a8061dc1305136c6c22b8baf0c0127a9");
    }

    test("should keep the state when finishing") {
        let key: u8[32] = undefined;
        void try decodeHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", &key);
        let mac = try Poly1305.init(&key);
        mac.update("Cryptographic Fo");
        const early = mac.finish();
        let earlyDigits: u8[32] = undefined;
        const earlyText: string = try encodeHex(&early, &earlyDigits);
        expect(earlyText).toBe("fd861c7184f98f45dc6d5b4dc6c081e4");
        mac.update("rum Research Group");
        const tag = mac.finish();
        let digits: u8[32] = undefined;
        const text: string = try encodeHex(&tag, &digits);
        expect(text).toBe("a8061dc1305136c6c22b8baf0c0127a9");
    }

    test("should buffer a tail across several full blocks") {
        let key: u8[32] = undefined;
        void try decodeHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", &key);
        let message: u8[100] = undefined;
        for (const _, i of message) message[i] = 'a';
        let mac = try Poly1305.init(&key);
        mac.update(message[0..7]);
        mac.update(message[7..60]);
        mac.update(message[60..100]);
        expect(mac.used).toBe(4);
        const tag = mac.finish();
        let digits: u8[32] = undefined;
        const text: string = try encodeHex(&tag, &digits);
        expect(text).toBe("bd1438e643889e46cc995ce5b6e1eb13");
    }

    test("should start from a zero accumulator") {
        let key: u8[32] = undefined;
        for (const _, i of key) key[i] = 0xFF;
        const mac = try Poly1305.init(&key);
        expect(mac.h[0]).toBe(0);
        expect(mac.used).toBe(0);
        expect(mac.r[4]).toBe(0x00F_FFFF);
    }
}
