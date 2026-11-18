/**
 * Imports
 */

import { fnv1a32, fnv1a64 } from "@fnv";

/**
 * Tests
 */

/**
 * The input that the specs hash prefixes of.
 *
 * @remarks
 * Its 62 distinct characters make every prefix hash differently.
 *
 * @since 1.0.0
 */

const Text = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

describe("fnv1a32") {
    test("should give the offset basis for no bytes") {
        expect(fnv1a32("")).toBe(0x811C_9DC5);
    }

    test("should match the published values") {
        expect(fnv1a32("a")).toBe(0xE40C_292C);
        expect(fnv1a32("foobar")).toBe(0xBF9C_F968);
    }

    test("should match the reference on longer inputs") {
        expect(fnv1a32(Text[0..1])).toBe(0x350C_A8AF);
        expect(fnv1a32(Text[0..16])).toBe(0x87BC_333D);
        expect(fnv1a32(Text)).toBe(0x8AC0_6BEE);
    }
}

describe("fnv1a64") {
    test("should give the offset basis for no bytes") {
        expect(fnv1a64("")).toBe(0xCBF2_9CE4_8422_2325);
    }

    test("should match the published values") {
        expect(fnv1a64("a")).toBe(0xAF63_DC4C_8601_EC8C);
        expect(fnv1a64("foobar")).toBe(0x8594_4171_F739_67E8);
    }

    test("should match the reference on longer inputs") {
        expect(fnv1a64(Text[0..1])).toBe(0xAF63_AD4C_8601_9CAF);
        expect(fnv1a64(Text[0..16])).toBe(0x2E37_3913_E5AD_677D);
        expect(fnv1a64(Text)).toBe(0x84C4_7131_3002_FCAE);
    }
}
