/**
 * Imports
 */

import { free } from "./heap";
import { FormatError } from "./fmt";
import { baseName, extension, isAbsolute, isSeparator, join, joinInto, parent } from "./path";

/**
 * Tests
 */

describe("isSeparator") {
    test("should accept a slash") {
        expect(isSeparator('/')).toBe(true);
    }

    test("should refuse a letter") {
        expect(isSeparator('a')).toBe(false);
    }
}

describe("isAbsolute") {
    test("should accept a path from the root") {
        expect(isAbsolute("/usr/lib")).toBe(true);
    }

    test("should refuse a relative path") {
        expect(isAbsolute("usr/lib")).toBe(false);
        expect(isAbsolute("")).toBe(false);
    }
}

describe("joinInto") {
    test("should put one slash between the parts") {
        let buf: u8[64] = undefined;
        const path: string = try joinInto(&buf, "out", "a.txt");

        expect(path).toBe("out/a.txt");
    }

    test("should not double a slash that the folder ends with") {
        let buf: u8[64] = undefined;
        const path: string = try joinInto(&buf, "out/", "a.txt");

        expect(path).toBe("out/a.txt");
    }

    test("should leave the name as it is for an empty folder") {
        let buf: u8[64] = undefined;
        const path: string = try joinInto(&buf, "", "a.txt");

        expect(path).toBe("a.txt");
    }

    test("should throw NoSpaceLeft when the buffer is too small") {
        let buf: u8[4] = undefined;
        expect(joinInto(&buf, "out", "a.txt")).toThrow(FormatError.NoSpaceLeft);
    }
}

describe("join") {
    test("should allocate the joined path") {
        const bytes = try join(testing.allocator, "build", "out.o");
        defer free(testing.allocator, bytes);
        const path: string = bytes;

        expect(path).toBe("build/out.o");
    }
}

describe("baseName") {
    test("should return the last name") {
        expect(baseName("src/lib/main.hx")).toBe("main.hx");
    }

    test("should ignore separators at the end") {
        expect(baseName("src/lib/")).toBe("lib");
    }

    test("should keep a lone name and the root") {
        expect(baseName("main.hx")).toBe("main.hx");
        expect(baseName("/")).toBe("/");
    }
}

describe("parent") {
    test("should return the folder of the last name") {
        expect(parent("src/lib/main.hx") ?? "-").toBe("src/lib");
        expect(parent("src/lib/") ?? "-").toBe("src");
    }

    test("should keep the root") {
        expect(parent("/main.hx") ?? "-").toBe("/");
    }

    test("should return null for a single name or the root") {
        expect(parent("main.hx") == null).toBe(true);
        expect(parent("/") == null).toBe(true);
    }
}

describe("extension") {
    test("should return the part from the last dot") {
        expect(extension("pkg/a.tar.gz")).toBe(".gz");
    }

    test("should be empty without a dot") {
        expect(extension("Makefile")).toBe("");
        expect(extension("v1.2/Makefile")).toBe("");
    }

    test("should not count a leading dot") {
        expect(extension(".profile")).toBe("");
    }
}
