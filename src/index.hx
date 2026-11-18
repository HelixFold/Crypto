/**
 * @helix/crypto computes checksums and message authentication codes in pure Helix, on any target.
 *
 * @remarks
 * Nothing here allocates or needs an OS, so the same code runs on a desktop, in WASI, or on a microcontroller.
 * Every checksum and MAC has a one-call function for bytes at hand and a struct for bytes that arrive in pieces.
 * It has its own SHA-256 and needs nothing from `std` beyond the allocator that scrypt takes.
 *
 * @example
 * ```hx
 * import { crc32, hmacSha256, verifyHmacSha256, encodeHex } from "@helix/crypto";
 *
 * crc32("123456789"); // 0xCBF43926
 * const tag = hmacSha256(key, message);
 * verifyHmacSha256(key, message, &tag); // true
 * let out: u8[64] = undefined;
 * try encodeHex(&tag, &out); // "5bdcc146..."
 * ```
 */

export { timingSafeEqual } from "@compare";
export { HexError, decodeHex, encodeHex } from "@hex";
export { HmacSha256, hmacSha256, verifyHmacSha256 } from "@hmac";
export { CRC32, CRC32BZip2, CRC64, crc32, crc32BZip2, crc64 } from "@crc";
