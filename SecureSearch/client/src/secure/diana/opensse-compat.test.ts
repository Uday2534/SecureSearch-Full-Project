import { describe, expect, it } from "vitest";
import vectors from "./fixtures/opensse-vectors.json";
import { bytesToHex, hexToBytes } from "./bytes.js";
import { blake2b512, chacha20Prg, hmacBlake2b } from "./primitives.js";
import { DianaClient, updateTokenAndMask } from "./diana.js";
import { createConstrainedRcpRf, evaluateConstrainedRange } from "./rcprf.js";

describe("OpenSSE Diana cross-language compatibility vectors", () => {
  const keywordBytes = new TextEncoder().encode(vectors.keyword);
  const keywordDigest = blake2b512(keywordBytes);
  const keywordIndex = keywordDigest.slice(0, 16);
  const rootKey = hmacBlake2b(new Uint8Array(32).fill(0x11), keywordIndex, 32);

  it("matches OpenSSE BLAKE2b keyword hashing and HMAC-BLAKE2b PRFs", () => {
    expect(bytesToHex(keywordIndex)).toBe(vectors.keywordIndex);
    expect(bytesToHex(rootKey)).toBe(vectors.rootKey);
    expect(bytesToHex(hmacBlake2b(new Uint8Array(32).fill(0x22), keywordIndex, 32)))
      .toBe(vectors.keywordToken);
  });

  it("matches OpenSSE ChaCha20 leaf expansion and update token/mask splitting", () => {
    for (const vector of vectors.leaves) {
      const leafKey = hexToBytes(vector.leafKey);
      const stream = chacha20Prg(leafKey, 0, 24);
      expect(bytesToHex(stream.slice(0, 16))).toBe(vector.updateToken);
      expect(bytesToHex(stream.slice(16, 24))).toBe(vector.mask);
      const split = updateTokenAndMask(leafKey);
      expect(bytesToHex(split.token)).toBe(vector.updateToken);
      expect(bytesToHex(split.mask)).toBe(vector.mask);
    }
  });

  it("matches OpenSSE 48-level GGM/RCPRF evaluations for leaves 0, 1 and 2", () => {
    const constrained = createConstrainedRcpRf(rootKey, 0n, 2n);
    const evaluated = evaluateConstrainedRange(constrained, 0n, 2n);
    expect(evaluated.map(({ leaf, value }) => ({
      leaf: Number(leaf), leafKey: bytesToHex(value),
    }))).toEqual(vectors.leaves.map(({ leaf, leafKey }) => ({ leaf, leafKey })));
  });

  it("matches the complete Diana keyword search token", () => {
    const client = DianaClient.fromMasterKeys(
      new Uint8Array(32).fill(0x11),
      new Uint8Array(32).fill(0x22),
    );
    // The deterministic reference client has three prior updates for this keyword.
    const state = JSON.parse(client.serializeState());
    state.counters = [[vectors.keyword, 3]];
    const restored = DianaClient.restoreState(JSON.stringify(state));
    expect(bytesToHex(restored.search(vectors.keyword).keywordToken))
      .toBe(vectors.keywordToken);
    expect(restored.searchAddresses(vectors.keyword).map(({ address }) => bytesToHex(address)))
      .toEqual(vectors.leaves.map(({ updateToken }) => updateToken));
  });
});
