/**
 * Imports
 */

import { timingSafeEqual } from "@compare";

/**
 * Tests
 */

describe("timingSafeEqual") {
    test("should accept equal bytes") {
        expect(timingSafeEqual("abc", "abc")).toBeTrue();
        expect(timingSafeEqual("", "")).toBeTrue();
    }

    test("should reject a difference at any position") {
        expect(timingSafeEqual("abc", "xbc")).toBeFalse();
        expect(timingSafeEqual("abc", "axc")).toBeFalse();
        expect(timingSafeEqual("abc", "abx")).toBeFalse();
    }

    test("should reject different lengths") {
        expect(timingSafeEqual("abc", "ab")).toBeFalse();
        expect(timingSafeEqual("", "a")).toBeFalse();
    }

    test("should reject bytes that differ in one bit only") {
        expect(timingSafeEqual("\x00", "\x80")).toBeFalse();
        expect(timingSafeEqual("\x00", "\x01")).toBeFalse();
    }
}
