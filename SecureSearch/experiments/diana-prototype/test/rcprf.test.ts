import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { bytesToHex, hexToBytes } from "../src/bytes.js";
import {
  createConstrainedRcpRf,
  deserializeConstrained,
  DIANA_MAX_LEAF,
  evaluateConstrained,
  evaluateConstrainedRange,
  serializeConstrained,
} from "../src/rcprf.js";

interface Vectors {
  rcprf48Range0To2: {
    rootKeyHex: string;
    range: [number, number];
    serializedHex: string;
    leafOutputsHex: string[];
  };
}

const vectors = JSON.parse(
  await readFile(
    fileURLToPath(new URL("../../test-vectors.json", import.meta.url)),
    "utf8",
  ),
) as Vectors;

test("RCPRF prefix constraint matches the recorded source-translation vector", () => {
  const vector = vectors.rcprf48Range0To2;
  const constrained = createConstrainedRcpRf(
    hexToBytes(vector.rootKeyHex),
    BigInt(vector.range[0]),
    BigInt(vector.range[1]),
  );
  const serialized = serializeConstrained(constrained);
  assert.equal(bytesToHex(serialized), vector.serializedHex);
  assert.deepEqual(
    evaluateConstrainedRange(constrained, 0n, 2n).map(({ value }) =>
      bytesToHex(value),
    ),
    vector.leafOutputsHex,
  );
});

test("constrained evaluation equals root evaluation inside arbitrary ranges", () => {
  const rootKey = Uint8Array.from({ length: 32 }, (_, i) => i);
  const ranges: Array<[bigint, bigint]> = [
    [0n, 0n],
    [0n, 31n],
    [17n, 89n],
    [DIANA_MAX_LEAF - 12n, DIANA_MAX_LEAF],
  ];
  for (const [min, max] of ranges) {
    const constrained = createConstrainedRcpRf(rootKey, min, max);
    for (let leaf = min; leaf <= max; leaf++) {
      const singleLeaf = createConstrainedRcpRf(rootKey, leaf, leaf);
      assert.deepEqual(
        evaluateConstrained(constrained, leaf),
        evaluateConstrained(singleLeaf, leaf),
      );
    }
  }
});

test("serialized constrained keys round-trip and reject index n", () => {
  const rootKey = new Uint8Array(32).fill(0xa5);
  const constrained = createConstrainedRcpRf(rootKey, 0n, 6n);
  const decoded = deserializeConstrained(serializeConstrained(constrained));
  for (let leaf = 0n; leaf <= 6n; leaf++) {
    assert.deepEqual(
      evaluateConstrained(decoded, leaf),
      evaluateConstrained(constrained, leaf),
    );
  }
  assert.throws(() => evaluateConstrained(decoded, 7n), RangeError);
});

test("constrained-key parser rejects truncation, trailing bytes, bad ranges, and bad counts", () => {
  const constrained = createConstrainedRcpRf(new Uint8Array(32).fill(7), 0n, 3n);
  const encoded = serializeConstrained(constrained);
  assert.throws(() => deserializeConstrained(encoded.slice(0, -1)));
  assert.throws(() => deserializeConstrained(new Uint8Array([...encoded, 0])));

  const badHeight = encoded.slice();
  badHeight[0] = 47;
  assert.throws(() => deserializeConstrained(badHeight));

  const badCount = encoded.slice();
  new DataView(badCount.buffer).setUint32(1, 0xffff_ffff, true);
  assert.throws(() => deserializeConstrained(badCount));

  const badSubtree = encoded.slice();
  badSubtree[5] = 0;
  assert.throws(() => deserializeConstrained(badSubtree));
});

test("RCPRF rejects invalid and complete-tree constraints", () => {
  const key = new Uint8Array(32);
  assert.throws(() => createConstrainedRcpRf(key, 1n, 0n));
  assert.throws(() => createConstrainedRcpRf(key, 0n, DIANA_MAX_LEAF + 1n));
  assert.throws(() => createConstrainedRcpRf(key, 0n, DIANA_MAX_LEAF));
  assert.throws(() => createConstrainedRcpRf(key, -1n, 0n));
});
