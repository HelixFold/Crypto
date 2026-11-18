/**
 * Imports
 */

import { Allocator, alloc } from "./heap";
import { FormatError } from "./fmt";
import { Os, target } from "./target";

/**
 * Tells whether a byte separates the names in a path.
 *
 * @param c - The byte
 * @returns True for `/`, and on Windows for `\` as well
 *
 * @example
 * ```hx
 * isSeparator('/'); // true
 * isSeparator('\\'); // true only in a build for Windows
 * ```
 *
 * @since 1.0.0
 */

export function isSeparator(c: u8): bool {
    if (comptime target.os == Os.Windows) return c == '/' || c == '\\';
    return c == '/';
}

/**
 * Tells whether a path starts at the root rather than at the current folder.
 *
 * @param path - The path
 * @returns True for a path that starts with a separator, and on Windows for one that starts with a drive such as `C:`
 *
 * @example
 * ```hx
 * isAbsolute("/usr/lib"); // true
 * isAbsolute("lib"); // false
 * ```
 *
 * @since 1.0.0
 */

export function isAbsolute(path: string): bool {
    if (path.len > 0 && isSeparator(path[0])) return true;
    if (comptime target.os == Os.Windows) return path.len >= 2 && path[1] == ':';
    return false;
}

/**
 * Joins a folder and a name with one separator between them, into `buf`.
 *
 * @param buf - Where the path goes
 * @param folder - The folder; an empty one leaves `name` as it is
 * @param name - The name, or a relative path, inside the folder
 * @returns The joined path, a part of `buf`, or `FormatError.NoSpaceLeft` when it doesn't fit
 *
 * @remarks
 * It adds `/` only when the folder doesn't end with a separator already, and allocates nothing,
 * so it suits a program without a heap. Windows accepts `/` as well as `\`.
 *
 * @example
 * ```hx
 * let buf: u8[256] = undefined;
 * try joinInto(&buf, "out", "a.txt"); // "out/a.txt"
 * try joinInto(&buf, "out/", "a.txt"); // "out/a.txt"
 * ```
 *
 * @see join
 *
 * @since 1.0.0
 */

export function joinInto(buf: u8[], folder: string, name: string): u8[] | Error {
    const slash = folder.len > 0 && !isSeparator(folder[folder.len - 1]);
    const at = folder.len + (slash ? 1 : 0);
    if (at + name.len > buf.len) throw FormatError.NoSpaceLeft;
    for (const c, i of folder) buf[i] = c;
    if (slash) buf[folder.len] = '/';
    for (const c, i of name) buf[at + i] = c;
    return buf[0..at + name.len];
}

/**
 * Joins a folder and a name with one separator between them, in new memory.
 *
 * @param a - The allocator that the path comes from
 * @param folder - The folder; an empty one leaves `name` as it is
 * @param name - The name, or a relative path, inside the folder
 * @returns The joined path, owned by the caller, or the allocator's error
 *
 * @example
 * ```hx
 * const path = try join(a, "build", "out.o"); // "build/out.o"
 * defer free(a, path);
 * ```
 *
 * @see joinInto
 *
 * @since 1.0.0
 */

export function join(a: dyn Allocator, folder: string, name: string): u8[] | Error {
    const slash = folder.len > 0 && !isSeparator(folder[folder.len - 1]);
    const out = try alloc<u8>(a, folder.len + (slash ? 1 : 0) + name.len);
    return try joinInto(out, folder, name);
}

/**
 * Leaves out the separators at the end of a path, but keeps a root on its own.
 *
 * @since 1.0.0
 */

function trimEnd(path: string): string {
    let end = path.len;
    while (end > 1 && isSeparator(path[end - 1])) end -= 1;
    return path[0..end];
}

/**
 * Returns the last name in a path.
 *
 * @param path - The path
 * @returns The part after the last separator, ignoring separators at the end; the root stays as it is
 *
 * @example
 * ```hx
 * baseName("src/lib/main.hx"); // "main.hx"
 * baseName("src/lib/"); // "lib"
 * baseName("main.hx"); // "main.hx"
 * ```
 *
 * @since 1.0.0
 */

export function baseName(path: string): string {
    const trimmed = trimEnd(path);
    if (trimmed.len == 1 && isSeparator(trimmed[0])) return trimmed;
    let i = trimmed.len;
    while (i > 0 && !isSeparator(trimmed[i - 1])) i -= 1;
    return trimmed[i..trimmed.len];
}

/**
 * Returns the folder that holds the last name in a path.
 *
 * @param path - The path
 * @returns Everything before the last name, without the separator, or null for a single name or the root
 *
 * @remarks
 * It works on the text only and doesn't look at the file system, so `..` is a name like any other.
 *
 * @example
 * ```hx
 * parent("src/lib/main.hx"); // "src/lib"
 * parent("/main.hx"); // "/"
 * parent("main.hx"); // null
 * ```
 *
 * @since 1.0.0
 */

export function parent(path: string): ?string {
    const trimmed = trimEnd(path);
    let i = trimmed.len;
    while (i > 0 && !isSeparator(trimmed[i - 1])) i -= 1;
    if (i == 0 || i == trimmed.len) return null;
    let end = i;
    while (end > 1 && isSeparator(trimmed[end - 1])) end -= 1;
    return trimmed[0..end];
}

/**
 * Returns the extension of the last name in a path.
 *
 * @param path - The path
 * @returns The part from the last `.` of the name on, such as `.gz`, or an empty string when the name has none
 *
 * @remarks
 * A name that only starts with a dot, such as `.profile`, has no extension.
 *
 * @example
 * ```hx
 * extension("pkg/a.tar.gz"); // ".gz"
 * extension("Makefile"); // ""
 * extension(".profile"); // ""
 * ```
 *
 * @since 1.0.0
 */

export function extension(path: string): string {
    const name = baseName(path);
    let i = name.len;
    while (i > 1) {
        i -= 1;
        if (name[i] == '.') return name[i..name.len];
    }
    return name[0..0];
}
