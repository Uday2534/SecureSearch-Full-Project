import { chacha20orig } from "@noble/ciphers/chacha";
import { blake2b } from "@noble/hashes/blake2b";
import { hmac } from "@noble/hashes/hmac";
import { assertLength } from "./bytes.js";

export const KEY_BYTES = 32;
export const BLAKE2B_BYTES = 64;
const CHACHA_NONCE = new Uint8Array(8);
const CHACHA_BLOCK_BYTES = 64;

export function blake2b512(message: Uint8Array): Uint8Array {
  return blake2b(message, { dkLen: BLAKE2B_BYTES });
}

export function hmacBlake2b(
  key: Uint8Array,
  message: Uint8Array,
  outputLength = BLAKE2B_BYTES,
): Uint8Array {
  if (key.length === 0) {
    throw new RangeError("HMAC key must not be empty");
  }
  if (!Number.isInteger(outputLength) || outputLength < 1 || outputLength > 64) {
    throw new RangeError("HMAC output length must be between 1 and 64 bytes");
  }
  return hmac(blake2b, key, message).slice(0, outputLength);
}

export function chacha20Prg(
  key: Uint8Array,
  offset: number,
  length: number,
): Uint8Array {
  assertLength(key, KEY_BYTES, "ChaCha20 key");
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new RangeError("PRG offset must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError("PRG length must be a non-negative safe integer");
  }
  if (length === 0) {
    return new Uint8Array();
  }

  const startBlock = Math.floor(offset / CHACHA_BLOCK_BYTES);
  const inBlockOffset = offset % CHACHA_BLOCK_BYTES;
  const requiredBytes = inBlockOffset + length;
  const blockCount = Math.ceil(requiredBytes / CHACHA_BLOCK_BYTES);
  const zeros = new Uint8Array(blockCount * CHACHA_BLOCK_BYTES);
  const stream = chacha20orig(
    key,
    CHACHA_NONCE,
    zeros,
    undefined,
    startBlock,
  );
  return stream.slice(inBlockOffset, inBlockOffset + length);
}

export function derivePrgKey(key: Uint8Array, branch: 0 | 1): Uint8Array {
  return chacha20Prg(key, branch * KEY_BYTES, KEY_BYTES);
}
