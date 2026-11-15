import { describe, expect, it } from "vitest";
import {
  assertLength, bytesToHex, concatBytes, hexToBytes,
  uint64FromLittleEndian, uint64ToLittleEndian, xorBytes,
} from "./bytes.js";

describe("Diana byte utilities", () => {
  it("round-trips hexadecimal bytes", () => {
    const input = new Uint8Array([0, 1, 15, 16, 127, 255]);
    expect(hexToBytes(bytesToHex(input))).toEqual(input);
  });

  it("rejects malformed hexadecimal input", () => {
    expect(() => hexToBytes("abc")).toThrow();
    expect(() => hexToBytes("0xz1")).toThrow();
  });

  it("round-trips unsigned 64-bit little-endian document indexes", () => {
    for (const value of [0n, 1n, 255n, 256n, 0x0102030405060708n, 0xffff_ffff_ffff_ffffn]) {
      expect(uint64FromLittleEndian(uint64ToLittleEndian(value))).toBe(value);
    }
    expect(() => uint64ToLittleEndian(-1n)).toThrow(RangeError);
    expect(() => uint64ToLittleEndian(0x1_0000_0000_0000_0000n)).toThrow(RangeError);
  });

  it("XOR is reversible and rejects unequal lengths", () => {
    const left = new Uint8Array([1, 2, 3]);
    const right = new Uint8Array([7, 8, 9]);
    expect(xorBytes(xorBytes(left, right), right)).toEqual(left);
    expect(() => xorBytes(left, new Uint8Array([1]))).toThrow(RangeError);
  });

  it("concatenates without changing input arrays", () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3]);
    expect(concatBytes(a, b)).toEqual(new Uint8Array([1, 2, 3]));
    expect(a).toEqual(new Uint8Array([1, 2]));
    expect(() => assertLength(a, 3, "test")).toThrow(RangeError);
  });
});
