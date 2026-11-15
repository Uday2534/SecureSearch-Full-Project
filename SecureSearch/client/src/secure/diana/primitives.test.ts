import { describe, expect, it } from "vitest";
import { blake2b512, chacha20Prg, derivePrgKey, hmacBlake2b, KEY_BYTES } from "./primitives.js";

describe("Diana cryptographic primitive wrappers", () => {
  it("returns a 64-byte BLAKE2b-512 digest and is deterministic", () => {
    const message = new TextEncoder().encode("SecureSearch test vector");
    const first = blake2b512(message);
    expect(first).toHaveLength(64);
    expect(blake2b512(message)).toEqual(first);
    expect(blake2b512(new TextEncoder().encode("different"))).not.toEqual(first);
  });

  it("truncates HMAC-BLAKE2b to the requested output length", () => {
    const key = new Uint8Array(KEY_BYTES).fill(0x42);
    const message = new TextEncoder().encode("keyword");
    expect(hmacBlake2b(key, message, 32)).toHaveLength(32);
    expect(hmacBlake2b(key, message, 32)).toEqual(hmacBlake2b(key, message, 32));
    expect(hmacBlake2b(key, message, 32)).not.toEqual(hmacBlake2b(key, message, 16));
    expect(() => hmacBlake2b(new Uint8Array(), message)).toThrow(RangeError);
    expect(() => hmacBlake2b(key, message, 0)).toThrow(RangeError);
  });

  it("implements consistent ChaCha20 PRG slices", () => {
    const key = new Uint8Array(KEY_BYTES).map((_, i) => i);
    const full = chacha20Prg(key, 0, 160);
    expect(chacha20Prg(key, 17, 31)).toEqual(full.slice(17, 48));
    expect(chacha20Prg(key, 64, 64)).toEqual(full.slice(64, 128));
    expect(chacha20Prg(key, 0, 0)).toEqual(new Uint8Array());
    expect(() => chacha20Prg(new Uint8Array(3), 0, 1)).toThrow();
    expect(() => chacha20Prg(key, -1, 1)).toThrow(RangeError);
  });

  it("derives distinct branch keys", () => {
    const key = new Uint8Array(KEY_BYTES).fill(9);
    expect(derivePrgKey(key, 0)).toHaveLength(KEY_BYTES);
    expect(derivePrgKey(key, 0)).not.toEqual(derivePrgKey(key, 1));
  });
});
