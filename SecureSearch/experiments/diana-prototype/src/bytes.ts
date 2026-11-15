export function assertLength(
  value: Uint8Array,
  length: number,
  name: string,
): void {
  if (value.length !== length) {
    throw new RangeError(`${name} must be ${length} bytes`);
  }
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(
    parts.reduce((total, part) => total + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function hexToBytes(hex: string, name = "hex"): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new TypeError(`${name} must be an even-length hexadecimal string`);
  }
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

export function xorBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length !== right.length) {
    throw new RangeError("XOR inputs must have equal lengths");
  }
  const result = new Uint8Array(left.length);
  for (let i = 0; i < left.length; i++) {
    result[i] = left[i]! ^ right[i]!;
  }
  return result;
}

export function uint64ToLittleEndian(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError("document index must be an unsigned 64-bit integer");
  }
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigUint64(0, value, true);
  return result;
}

export function uint64FromLittleEndian(bytes: Uint8Array): bigint {
  assertLength(bytes, 8, "uint64");
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    .getBigUint64(0, true);
}
