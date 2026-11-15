import assert from "node:assert/strict";
import { createCipheriv, createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  bytesToHex,
  hexToBytes,
} from "../src/bytes.js";
import {
  blake2b512,
  chacha20Prg,
  hmacBlake2b,
} from "../src/primitives.js";

interface Vectors {
  blake2b512: Array<{ inputHex: string; outputHex: string }>;
  hmacBlake2b512: {
    keyHex: string;
    messageHex: string;
    outputHex: string;
  };
  chacha20Original: {
    keyHex: string;
    nonceHex: string;
    counter: number;
    outputHex: string;
  };
}

const vectors = JSON.parse(
  await readFile(
    fileURLToPath(new URL("../../test-vectors.json", import.meta.url)),
    "utf8",
  ),
) as Vectors;

test("BLAKE2b-512 matches RFC 7693 vectors", () => {
  for (const vector of vectors.blake2b512) {
    assert.equal(
      bytesToHex(blake2b512(hexToBytes(vector.inputHex))),
      vector.outputHex,
    );
  }
});

test("HMAC-BLAKE2b matches Node/OpenSSL independently", () => {
  const { keyHex, messageHex, outputHex } = vectors.hmacBlake2b512;
  const key = hexToBytes(keyHex);
  const message = hexToBytes(messageHex);
  const nodeOutput = createHmac("blake2b512", key).update(message).digest();
  assert.equal(bytesToHex(nodeOutput), outputHex);
  assert.equal(bytesToHex(hmacBlake2b(key, message)), outputHex);
  assert.equal(bytesToHex(hmacBlake2b(key, message, 32)), outputHex.slice(0, 64));
});

test("original ChaCha20 PRG matches Node/OpenSSL at block and byte offsets", () => {
  const { keyHex, outputHex } = vectors.chacha20Original;
  const key = hexToBytes(keyHex);
  const expected = hexToBytes(outputHex);
  const nonce = hexToBytes(vectors.chacha20Original.nonceHex);
  const iv = new Uint8Array(16);
  iv.set(nonce, 8);
  new DataView(iv.buffer).setBigUint64(0, BigInt(vectors.chacha20Original.counter), true);
  const cipher = createCipheriv("chacha20", key, iv);
  const nodeOutput = Buffer.concat([
    cipher.update(new Uint8Array(64)),
    cipher.final(),
  ]);
  assert.equal(bytesToHex(nodeOutput), outputHex);
  assert.deepEqual(Uint8Array.from(nodeOutput), expected);
  assert.deepEqual(chacha20Prg(key, 0, 64), expected);
  assert.deepEqual(chacha20Prg(key, 32, 24), expected.slice(32, 56));

  const nextBlockIv = new Uint8Array(16);
  nextBlockIv.set(nonce, 8);
  new DataView(nextBlockIv.buffer).setBigUint64(0, 1n, true);
  const nextBlockCipher = createCipheriv("chacha20", key, nextBlockIv);
  const nextBlock = Buffer.concat([
    nextBlockCipher.update(new Uint8Array(64)),
    nextBlockCipher.final(),
  ]);
  assert.deepEqual(
    chacha20Prg(key, 64, 64),
    Uint8Array.from(nextBlock),
  );
});

test("primitive functions reject invalid parameters", () => {
  assert.throws(() => hmacBlake2b(new Uint8Array(), new Uint8Array()));
  assert.throws(() => hmacBlake2b(new Uint8Array([1]), new Uint8Array(), 65));
  assert.throws(() => chacha20Prg(new Uint8Array(31), 0, 1));
  assert.throws(() => chacha20Prg(new Uint8Array(32), -1, 1));
  assert.throws(() => chacha20Prg(new Uint8Array(32), 0, -1));
});
