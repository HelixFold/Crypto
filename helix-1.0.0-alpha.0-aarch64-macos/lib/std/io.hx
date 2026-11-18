/**
 * Anything that takes bytes, such as a file, a buffer, or a socket.
 *
 * @remarks
 * A struct implements it with one `write` method, and a pointer to the struct then converts to `dyn Writer`.
 * Formatting calls only `write`, so {@link fprint} and {@link fprintln} work with any writer.
 * Use {@link stdout} and {@link stderr} for the standard streams.
 *
 * @example
 * ```hx
 * const w: dyn Writer = stdout();
 * try fprint(w, `${1 + 1} items`); // prints 2 items
 * ```
 *
 * @since 1.0.0
 */

export interface Writer {
    /**
     * Takes all of the bytes, or fails.
     *
     * @param this - The writer
     * @param bytes - The bytes to take
     * @returns Nothing, or the error that stopped the write
     *
     * @remarks
     * A writer never takes part of the bytes, so a caller does not loop over short writes.
     *
     * @example
     * ```hx
     * try stdout().write("hi\n"); // prints hi
     * ```
     *
     * @since 1.0.0
     */

    write(this: *Self, bytes: readonly u8[]): void | Error;
}

/**
 * Anything that gives bytes, such as a file, stdin, or a socket.
 *
 * @remarks
 * A struct implements it with one `read` method, and a pointer to the struct then converts to `dyn Reader`.
 *
 * @example
 * ```hx
 * const r: dyn Reader = &file;
 * const n = try r.read(buffer); // the count of bytes read, 0 at the end
 * ```
 *
 * @since 1.0.0
 */

export interface Reader {
    /**
     * Reads bytes into a buffer.
     *
     * @param this - The reader
     * @param buf - The buffer to fill
     * @returns The number of bytes that it read, or 0 when there is nothing more, or the error that stopped the read
     *
     * @remarks
     * A read may fill only part of the buffer, so a caller loops until it gets 0.
     *
     * @example
     * ```hx
     * const n = try r.read(buffer); // 4, then 1, then 0 for a reader with 5 bytes and a buffer of 4
     * ```
     *
     * @since 1.0.0
     */

    read(this: *Self, buf: u8[]): usize | Error;
}

/**
 * Writes a template or a plain string to a writer.
 *
 * @param w - The writer
 * @param text - The template or the string
 * @returns Nothing, or the error that the writer threw
 *
 * @remarks
 * The template writes itself piece by piece, so the writer may get several calls for one template.
 * Nothing follows the text, so use {@link fprintln} to end the line.
 *
 * @example
 * ```hx
 * const n = 42;
 * try fprint(stderr(), `n=${n}`); // prints n=42 on stderr
 * ```
 *
 * @since 1.0.0
 */

export function fprint(w: dyn Writer, text: Format): void | Error {
    try text.writeTo(w);
}

/**
 * Writes a template or a plain string to a writer, then a newline.
 *
 * @param w - The writer
 * @param text - The template or the string
 * @returns Nothing, or the error that the writer threw
 *
 * @remarks
 * It works like {@link fprint} and writes the newline in a separate call to the writer.
 *
 * @example
 * ```hx
 * try fprintln(stdout(), "done"); // prints done and a newline
 * ```
 *
 * @since 1.0.0
 */

export function fprintln(w: dyn Writer, text: Format): void | Error {
    try text.writeTo(w);
    try w.write("\n");
}

/**
 * Writes bytes to a file descriptor.
 *
 * @remarks
 * The runtime in `lib/rt/runtime.c` implements it.
 * For descriptors 0 to 2 it writes to the buffered C stream, which `print` and `eprint` share,
 * and for any other descriptor it writes directly and retries on an interrupted call.
 *
 * @since 1.0.0
 */

extern "C" function hx_write(fd: i32, bytes: readonly u8[*], len: usize): void;

/**
 * The writer behind {@link stdout}.
 *
 * @remarks
 * It has no fields, since the C stream that it writes to keeps the buffer.
 *
 * @since 1.0.0
 */

struct Stdout {
    /**
     * Writes bytes to standard output.
     *
     * @param this - The writer
     * @param bytes - The bytes to write
     * @returns Nothing, since it never reports an error
     *
     * @remarks
     * The bytes go through the buffer that `print` uses, so the two keep their order.
     *
     * @since 1.0.0
     */

    write(this: *Stdout, bytes: readonly u8[]): void | Error {
        hx_write(1, bytes.ptr, bytes.len);
    }
}

/**
 * The writer behind {@link stderr}.
 *
 * @remarks
 * It has no fields, since the C stream that it writes to keeps the buffer.
 *
 * @since 1.0.0
 */

struct Stderr {
    /**
     * Writes bytes to standard error.
     *
     * @param this - The writer
     * @param bytes - The bytes to write
     * @returns Nothing, since it never reports an error
     *
     * @remarks
     * The bytes go through the buffer that `eprint` uses, so the two keep their order.
     *
     * @since 1.0.0
     */

    write(this: *Stderr, bytes: readonly u8[]): void | Error {
        hx_write(2, bytes.ptr, bytes.len);
    }
}

/**
 * The one writer for standard output.
 *
 * @remarks
 * It has no fields, so it needs no initialization.
 *
 * @since 1.0.0
 */

let stdoutWriter: Stdout = undefined;

/**
 * The one writer for standard error.
 *
 * @remarks
 * It has no fields, so it needs no initialization.
 *
 * @since 1.0.0
 */

let stderrWriter: Stderr = undefined;

/**
 * Returns the writer for standard output.
 *
 * @returns The writer
 *
 * @remarks
 * It shares its buffer with `print`, so output from both comes out in order.
 * Every call returns the same writer.
 *
 * @example
 * ```hx
 * print("a");
 * try stdout().write("b"); // stdout shows ab
 * ```
 *
 * @since 1.0.0
 */

export function stdout(): dyn Writer {
    return &stdoutWriter;
}

/**
 * Returns the writer for standard error.
 *
 * @returns The writer
 *
 * @remarks
 * It shares its buffer with `eprint`, so output from both comes out in order.
 * Every call returns the same writer.
 *
 * @example
 * ```hx
 * try fprintln(stderr(), "warning: disk almost full"); // prints the line on stderr
 * ```
 *
 * @since 1.0.0
 */

export function stderr(): dyn Writer {
    return &stderrWriter;
}

/* ---- buffered reading ---- */

/**
 * The errors of {@link BufferedReader}.
 *
 * @since 1.0.0
 */

export error IoError {
    /**
     * The source ended where a byte had to be.
     *
     * @example
     * ```hx
     * try reader.byte(); // throws IoError.EndOfStream after the last byte
     * ```
     *
     * @since 1.0.0
     */

    EndOfStream,
}

/**
 * The size of the buffer in a {@link BufferedReader}, and the most bytes that {@link BufferedReader.peek} can show.
 *
 * @remarks
 * It is small enough for a microcontroller's stack and large enough that a file read is rarely the bottleneck.
 *
 * @since 1.0.0
 */

export const BufferSize: usize = 8192;

/**
 * A reader that reads ahead, so a parser can look at bytes before it takes them.
 *
 * @remarks
 * Format detection peeks at the first bytes, and the decoder chosen afterwards reads those same bytes,
 * so a pipe or a socket works as well as a file.
 * Byte-at-a-time parsing through {@link next} or {@link byte} costs no call to the source until the buffer runs out.
 * A `*BufferedReader` is itself a `dyn Reader`.
 * The struct holds its buffer, about 8 KiB, so keep it where it stays put and pass a pointer.
 *
 * @example
 * ```hx
 * let file = try File.open("data.gz");
 * let input = BufferedReader { source: &file };
 * const magic = try input.peek(2);   // the bytes stay in the buffer
 * const first = try input.byte();    // 0x1f, the same first byte
 * ```
 *
 * @since 1.0.0
 */

export struct BufferedReader {
    /**
     * Where the bytes come from.
     *
     * @since 1.0.0
     */

    source: dyn Reader,

    /**
     * The bytes read from the source but not taken yet are `buffer[start..end]`.
     *
     * @since 1.0.0
     */

    buffer: u8[BufferSize] = undefined,
    start: usize = 0,
    end: usize = 0,

    /**
     * Whether the source has reported its end.
     *
     * @since 1.0.0
     */

    ended: bool = false,

    /**
     * Returns the bytes that are buffered, reading more when none are.
     *
     * @param this - The reader
     * @returns The buffered bytes, empty only at the end of the source, or the source's error
     *
     * @remarks
     * The bytes stay buffered until {@link consume} takes them.
     *
     * @example
     * ```hx
     * const data = try input.available();
     * input.consume(data.len); // took all of them
     * ```
     *
     * @since 1.0.0
     */

    available(this: *BufferedReader): readonly u8[] | Error {
        const all: u8[] = &this.buffer;
        if (this.start == this.end && !this.ended) {
            this.start = 0;
            this.end = try this.source.read(all);
            this.ended = this.end == 0;
        }
        return all[this.start..this.end];
    }

    /**
     * Reads until at least `count` bytes are buffered, or the source ends, without taking any.
     *
     * @param this - The reader
     * @param count - How many bytes the caller wants to see, at most {@link BufferSize}
     * @returns Every buffered byte, which may be more than `count`, and fewer only at the end of the source
     *
     * @example
     * ```hx
     * const magic = try input.peek(6);
     * if (magic.len >= 2 && magic[0] == 0x1f && magic[1] == 0x8b) {} // gzip
     * ```
     *
     * @since 1.0.0
     */

    peek(this: *BufferedReader, count: usize): readonly u8[] | Error {
        const all: u8[] = &this.buffer;
        if (this.start > 0) {
            const kept = this.end - this.start;
            for (const i of 0..kept) all[i] = all[this.start + i];
            this.start = 0;
            this.end = kept;
        }
        while (this.end < count && this.end < BufferSize && !this.ended) {
            const n = try this.source.read(all[this.end..BufferSize]);
            if (n == 0) this.ended = true;
            this.end += n;
        }
        return all[this.start..this.end];
    }

    /**
     * Takes `count` buffered bytes.
     *
     * @param this - The reader
     * @param count - How many bytes were used, at most as many as {@link available} or {@link peek} returned
     *
     * @since 1.0.0
     */

    consume(this: *BufferedReader, count: usize): void {
        this.start += count;
    }

    /**
     * Takes the next byte, or null at the end of the source.
     *
     * @param this - The reader
     * @returns The byte, null when the source has ended, or the source's error
     *
     * @example
     * ```hx
     * if (const b = try input.next()) seen(b); // nothing more when null
     * ```
     *
     * @since 1.0.0
     */

    next(this: *BufferedReader): ?u8 | Error {
        if (this.start == this.end) {
            const data = try this.available();
            if (data.len == 0) return null;
        }
        const b = this.buffer[this.start];
        this.start += 1;
        return b;
    }

    /**
     * Takes the next byte, which must exist.
     *
     * @param this - The reader
     * @returns The byte, or `IoError.EndOfStream` at the end of the source, or the source's error
     *
     * @example
     * ```hx
     * const flags = try input.byte();
     * ```
     *
     * @since 1.0.0
     */

    byte(this: *BufferedReader): u8 | Error {
        if (this.start < this.end) {
            const b = this.buffer[this.start];
            this.start += 1;
            return b;
        }
        const b = try this.next();
        if (b == null) throw IoError.EndOfStream;
        return b;
    }

    /**
     * Reads bytes into `buf`, from the buffer first.
     *
     * @param this - The reader
     * @param buf - Where the bytes go
     * @returns How many bytes were read, 0 at the end of the source, or the source's error
     *
     * @remarks
     * A read into a buffer at least as large as {@link BufferSize} goes straight to the source when nothing is buffered.
     *
     * @since 1.0.0
     */

    read(this: *BufferedReader, buf: u8[]): usize | Error {
        if (buf.len == 0) return 0;
        if (this.start == this.end && buf.len >= BufferSize && !this.ended) {
            const n = try this.source.read(buf);
            if (n == 0) this.ended = true;
            return n;
        }
        const data = try this.available();
        const n = data.len < buf.len ? data.len : buf.len;
        for (const i of 0..n) buf[i] = data[i];
        this.start += n;
        return n;
    }
}
