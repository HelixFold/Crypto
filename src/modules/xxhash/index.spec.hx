/**
 * Imports
 */

import { xxHash32, xxHash64 } from "@xxhash";

/**
 * Tests
 */

/**
 * The input that the specs hash prefixes of.
 *
 * @remarks
 * Its prefixes reach every path of both hashes, from no lanes to several stripes with each kind of tail.
 *
 * @since 1.0.0
 */

const Text = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

describe("xxHash32") {
    test("should match the published values") {
        expect(xxHash32("", 0)).toBe(0x02CC_5D05);
        expect(xxHash32("a", 0)).toBe(0x550D_7456);
        expect(xxHash32("abc", 0)).toBe(0x32D1_53FF);
        expect(xxHash32("Nobody inspects the spammish repetition", 0)).toBe(0xE229_3B2F);
    }

    test("should hash 1 bytes, the 1-byte tail") {
        expect(xxHash32(Text[0..1], 0)).toBe(0x4845_4CB2);
        expect(xxHash32(Text[0..1], 0x9E37_79B1)).toBe(0xC141_34F4);
    }

    test("should hash 3 bytes, three single bytes") {
        expect(xxHash32(Text[0..3], 0)).toBe(0x4800_9497);
        expect(xxHash32(Text[0..3], 0x9E37_79B1)).toBe(0xA2FF_873E);
    }

    test("should hash 4 bytes, one 4-byte word") {
        expect(xxHash32(Text[0..4], 0)).toBe(0x0A0B_4C93);
        expect(xxHash32(Text[0..4], 0x9E37_79B1)).toBe(0x9B08_3421);
    }

    test("should hash 7 bytes, a word and three single bytes") {
        expect(xxHash32(Text[0..7], 0)).toBe(0x1907_AD24);
        expect(xxHash32(Text[0..7], 0x9E37_79B1)).toBe(0x85E3_462B);
    }

    test("should hash 8 bytes, two words") {
        expect(xxHash32(Text[0..8], 0)).toBe(0x189B_BFBF);
        expect(xxHash32(Text[0..8], 0x9E37_79B1)).toBe(0xB7C1_0D19);
    }

    test("should hash 15 bytes, the longest input without lanes") {
        expect(xxHash32(Text[0..15], 0)).toBe(0x1DBD_FA0F);
        expect(xxHash32(Text[0..15], 0x9E37_79B1)).toBe(0x065E_1473);
    }

    test("should hash 16 bytes, exactly one stripe") {
        expect(xxHash32(Text[0..16], 0)).toBe(0xC2C4_5B69);
        expect(xxHash32(Text[0..16], 0x9E37_79B1)).toBe(0x72E8_FAF9);
    }

    test("should hash 17 bytes, one stripe and a single byte") {
        expect(xxHash32(Text[0..17], 0)).toBe(0xCC79_B217);
        expect(xxHash32(Text[0..17], 0x9E37_79B1)).toBe(0x498C_0EFA);
    }

    test("should hash 20 bytes, one stripe and a word") {
        expect(xxHash32(Text[0..20], 0)).toBe(0x3560_0916);
        expect(xxHash32(Text[0..20], 0x9E37_79B1)).toBe(0x418C_B782);
    }

    test("should hash 31 bytes, one stripe and every kind of tail") {
        expect(xxHash32(Text[0..31], 0)).toBe(0xA394_4879);
        expect(xxHash32(Text[0..31], 0x9E37_79B1)).toBe(0x8C8F_812D);
    }

    test("should hash 32 bytes, two stripes") {
        expect(xxHash32(Text[0..32], 0)).toBe(0xEFB1_272D);
        expect(xxHash32(Text[0..32], 0x9E37_79B1)).toBe(0xCBBC_3237);
    }

    test("should hash 62 bytes, three stripes and a tail") {
        expect(xxHash32(Text[0..62], 0)).toBe(0x2AEA_96E9);
        expect(xxHash32(Text[0..62], 0x9E37_79B1)).toBe(0xC7E4_DF44);
    }

    test("should let the seed change the hash of no bytes") {
        expect(xxHash32("", 0x9E37_79B1)).toBe(0x36B7_8AE7);
    }
}

describe("xxHash64") {
    test("should match the published values") {
        expect(xxHash64("", 0)).toBe(0xEF46_DB37_51D8_E999);
        expect(xxHash64("a", 0)).toBe(0xD24E_C4F1_A98C_6E5B);
        expect(xxHash64("abc", 0)).toBe(0x44BC_2CF5_AD77_0999);
        expect(xxHash64("Nobody inspects the spammish repetition", 0)).toBe(0xFBCE_A83C_8A37_8BF1);
    }

    test("should hash 1 bytes, the 1-byte tail") {
        expect(xxHash64(Text[0..1], 0)).toBe(0x6334_5708_1244_AFEC);
        expect(xxHash64(Text[0..1], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x4C1B_7395_7BF7_BC72);
    }

    test("should hash 3 bytes, three single bytes") {
        expect(xxHash64(Text[0..3], 0)).toBe(0x1C2D_CB4B_9024_D73D);
        expect(xxHash64(Text[0..3], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x0BA3_8AC2_7755_D9D9);
    }

    test("should hash 4 bytes, one 4-byte word") {
        expect(xxHash64(Text[0..4], 0)).toBe(0x4C33_072B_4564_7DCB);
        expect(xxHash64(Text[0..4], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x711B_A459_16A9_9723);
    }

    test("should hash 7 bytes, a 4-byte word and three single bytes") {
        expect(xxHash64(Text[0..7], 0)).toBe(0x97EE_4FE4_A0FF_4DFA);
        expect(xxHash64(Text[0..7], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x26CD_EB8C_F0A7_52B8);
    }

    test("should hash 8 bytes, one 8-byte word") {
        expect(xxHash64(Text[0..8], 0)).toBe(0xE4BA_22A4_9AD8_9D3F);
        expect(xxHash64(Text[0..8], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x6371_58C8_70C9_A5B0);
    }

    test("should hash 15 bytes, 8-byte, 4-byte, and single-byte tails") {
        expect(xxHash64(Text[0..15], 0)).toBe(0x4BB5_1A30_968E_6A4D);
        expect(xxHash64(Text[0..15], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x3A54_2516_5DC8_C3B0);
    }

    test("should hash 16 bytes, two 8-byte words") {
        expect(xxHash64(Text[0..16], 0)).toBe(0x5C5B_90C3_4E37_6D0B);
        expect(xxHash64(Text[0..16], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x63EE_660A_730A_A755);
    }

    test("should hash 31 bytes, the longest input without lanes") {
        expect(xxHash64(Text[0..31], 0)).toBe(0x80AD_FC1D_4202_0F39);
        expect(xxHash64(Text[0..31], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0xABDD_AE55_B3DC_A4A9);
    }

    test("should hash 32 bytes, exactly one stripe") {
        expect(xxHash64(Text[0..32], 0)).toBe(0xBF7C_9DBE_16B5_C6E2);
        expect(xxHash64(Text[0..32], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x81E5_374E_7CED_F1C5);
    }

    test("should hash 33 bytes, one stripe and a single byte") {
        expect(xxHash64(Text[0..33], 0)).toBe(0xE974_23E6_05E2_F3B4);
        expect(xxHash64(Text[0..33], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0xA482_D5F9_E702_8D13);
    }

    test("should hash 36 bytes, one stripe and a 4-byte word") {
        expect(xxHash64(Text[0..36], 0)).toBe(0x6919_6C1B_3AF0_BFF9);
        expect(xxHash64(Text[0..36], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0xDD07_0EC0_7C3D_3D57);
    }

    test("should hash 39 bytes, one stripe, a 4-byte word, and single bytes") {
        expect(xxHash64(Text[0..39], 0)).toBe(0x16AD_2D8A_60AD_5BC2);
        expect(xxHash64(Text[0..39], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x3404_E754_9640_C6C3);
    }

    test("should hash 40 bytes, one stripe and an 8-byte word") {
        expect(xxHash64(Text[0..40], 0)).toBe(0x1B3C_E041_C106_B50B);
        expect(xxHash64(Text[0..40], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x4BCF_9F9B_7744_CFC9);
    }

    test("should hash 62 bytes, one stripe and every kind of tail") {
        expect(xxHash64(Text[0..62], 0)).toBe(0x7639_D419_DE61_4EED);
        expect(xxHash64(Text[0..62], 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x9146_6C8A_5CC7_7EB1);
    }

    test("should let the seed change the hash of no bytes") {
        expect(xxHash64("", 0xFFFF_FFFF_FFFF_FFFF)).toBe(0x298F_4C84_B24F_5380);
    }
}
