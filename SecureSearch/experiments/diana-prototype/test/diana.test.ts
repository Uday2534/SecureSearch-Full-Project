import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { bytesToHex } from "../src/bytes.js";
import {
  DianaClient,
  DianaServer,
  MAX_ADD_COUNT,
} from "../src/diana.js";
import {
  assertConstrainedPrefix,
  deserializeConstrained,
  evaluateConstrained,
} from "../src/rcprf.js";

interface DianaVector {
  derivationMasterKeyHex: string;
  keywordTokenMasterKeyHex: string;
  keyword: string;
  documentIndices: string[];
  updateTokensHex: string[];
  maskedIndicesHex: string[];
  keywordTokenHex: string;
  constrainedKeyHex: string;
}

interface Vectors {
  dianaUpdates: DianaVector;
}

const vectors = JSON.parse(
  await readFile(
    fileURLToPath(new URL("../../test-vectors.json", import.meta.url)),
    "utf8",
  ),
) as Vectors;

function vectorClient(): DianaClient {
  const vector = vectors.dianaUpdates;
  return DianaClient.fromMasterKeys(
    Buffer.from(vector.derivationMasterKeyHex, "hex"),
    Buffer.from(vector.keywordTokenMasterKeyHex, "hex"),
  );
}

test("Diana deterministic updates and search match regression vectors", () => {
  const vector = vectors.dianaUpdates;
  const client = vectorClient();
  const server = new DianaServer();
  vector.documentIndices.forEach((value, i) => {
    const update = client.update(vector.keyword, BigInt(value));
    assert.equal(bytesToHex(update.token), vector.updateTokensHex[i]);
    assert.equal(bytesToHex(update.index), vector.maskedIndicesHex[i]);
    server.insert(update);
  });

  const search = client.search(vector.keyword);
  assert.equal(search.addCount, vector.documentIndices.length);
  assert.equal(bytesToHex(search.keywordToken), vector.keywordTokenHex);
  assert.equal(bytesToHex(search.constrainedKey!), vector.constrainedKeyHex);
  assert.deepEqual(
    server.search(search),
    vector.documentIndices.map(BigInt),
  );
});

test("server evaluates every authorized historical leaf and no later leaf", () => {
  const client = vectorClient();
  const server = new DianaServer();
  for (let i = 0n; i < 9n; i++) {
    server.insert(client.update("history", i));
  }
  const request = client.search("history");
  assert.equal(request.addCount, 9);
  const leaves = server.evaluateSearchLeaves(request);
  assert.deepEqual(leaves.map(({ leaf }) => leaf), [
    0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n,
  ]);
  const constrained = deserializeConstrained(request.constrainedKey!);
  assertConstrainedPrefix(constrained, 9);
  assert.throws(() => evaluateConstrained(constrained, 9n), RangeError);
});

test("different keywords have isolated counters and searchable postings", () => {
  const client = vectorClient();
  const server = new DianaServer();
  server.insert(client.update("alpha", 10n));
  server.insert(client.update("beta", 20n));
  server.insert(client.update("alpha", 30n));

  assert.equal(client.getCount("alpha"), 2);
  assert.equal(client.getCount("beta"), 1);
  assert.deepEqual(server.search(client.search("alpha")), [10n, 30n]);
  assert.deepEqual(server.search(client.search("beta")), [20n]);
  assert.deepEqual(server.search(client.search("missing")), []);
});

test("repeated keyword/document updates receive distinct addresses", () => {
  const client = vectorClient();
  const server = new DianaServer();
  const first = client.update("repeat", 7n);
  const second = client.update("repeat", 7n);
  assert.notEqual(bytesToHex(first.token), bytesToHex(second.token));
  server.insert(first);
  server.insert(second);
  assert.deepEqual(server.search(client.search("repeat")), [7n, 7n]);
});

test("client state round-trips counters without changing subsequent tokens", () => {
  const client = vectorClient();
  const server = new DianaServer();
  server.insert(client.update("stateful", 42n));
  const restored = DianaClient.restoreState(client.serializeState());
  assert.equal(restored.getCount("stateful"), 1);

  server.insert(restored.update("stateful", 43n));
  assert.deepEqual(server.search(restored.search("stateful")), [42n, 43n]);
});

test("counter boundaries and invalid inputs fail before changing state", () => {
  const client = vectorClient();
  assert.throws(() => client.update("", 1n));
  assert.throws(() => client.update("negative-index", -1n));
  assert.throws(() => client.update("wide-index", 0x1_0000_0000_0000_0000n));
  assert.equal(client.getCount("negative-index"), 0);

  const state = JSON.parse(client.serializeState()) as {
    counters: Array<[string, number]>;
  };
  state.counters.push(["last-valid-count", MAX_ADD_COUNT - 1]);
  state.counters.push(["boundary", MAX_ADD_COUNT]);
  const boundaryClient = DianaClient.restoreState(JSON.stringify(state));
  const finalValidUpdate = boundaryClient.update("last-valid-count", 3n);
  assert.equal(finalValidUpdate.token.length, 16);
  assert.equal(boundaryClient.getCount("last-valid-count"), MAX_ADD_COUNT);
  assert.throws(
    () => boundaryClient.update("last-valid-count", 4n),
    /uint32 add_count limit/,
  );
  assert.equal(boundaryClient.getCount("boundary"), MAX_ADD_COUNT);
  assert.throws(
    () => boundaryClient.update("boundary", 1n),
    /uint32 add_count limit/,
  );
  assert.throws(
    () =>
      DianaClient.restoreState(
        JSON.stringify({
          ...state,
          counters: [["invalid", MAX_ADD_COUNT + 1]],
        }),
      ),
    /unsigned 32-bit count/,
  );
});

test("server rejects missing entries and malformed search tokens", () => {
  const client = vectorClient();
  client.update("missing-entry", 1n);
  const request = client.search("missing-entry");
  const emptyServer = new DianaServer();
  assert.throws(() => emptyServer.search(request), /missing Diana update entry/);
  assert.throws(
    () => emptyServer.search({ ...request, addCount: MAX_ADD_COUNT + 1 }),
    /exceeds uint32/,
  );
  assert.throws(
    () => emptyServer.search({ ...request, constrainedKey: null }),
    /requires a constrained key/,
  );
});
