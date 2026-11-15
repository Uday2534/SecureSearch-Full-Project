import { describe, expect, it } from "vitest";
import { bytesToHex } from "./bytes.js";
import { DianaClient, DianaServer } from "./diana.js";
import { createConstrainedRcpRf, deserializeConstrained, evaluateConstrainedRange, serializeConstrained } from "./rcprf.js";

const keyA = new Uint8Array(32).fill(0x11);
const keyB = new Uint8Array(32).fill(0x22);
const makeClient = () => DianaClient.fromMasterKeys(keyA, keyB);

describe("Diana client update/search state", () => {
  it("does not advance the keyword counter until an update is committed", () => {
    const client = makeClient();
    const pending = client.prepareUpdate("cloud", 7n);
    expect(client.getCount("cloud")).toBe(0);
    expect(pending.expectedCount).toBe(0);
    client.commitUpdate("cloud", pending.expectedCount);
    expect(client.getCount("cloud")).toBe(1);
  });

  it("rejects stale or duplicate state commits", () => {
    const client = makeClient();
    const first = client.prepareUpdate("cloud", 1n);
    client.commitUpdate("cloud", first.expectedCount);
    expect(() => client.commitUpdate("cloud", first.expectedCount)).toThrow(/state changed/);
  });

  it("supports sequential updates and retrieves the expected document indexes", () => {
    const client = makeClient();
    const server = new DianaServer();

    for (const documentIndex of [7n, 8n, 19n]) {
      const pending = client.prepareUpdate("cloud", documentIndex);
      server.insert(pending.request);
      client.commitUpdate("cloud", pending.expectedCount);
    }

    expect(client.getCount("cloud")).toBe(3);
    expect(server.search(client.search("cloud"))).toEqual([7n, 8n, 19n]);
  });

  it("derives exactly the same update addresses as the committed server entries", () => {
    const client = makeClient();
    const server = new DianaServer();
    const expectedAddresses: string[] = [];

    for (const documentIndex of [3n, 5n]) {
      const pending = client.prepareUpdate("security", documentIndex);
      expectedAddresses.push(bytesToHex(pending.request.token));
      server.insert(pending.request);
      client.commitUpdate("security", pending.expectedCount);
    }

    expect(client.searchAddresses("security").map((item) => bytesToHex(item.address))).toEqual(expectedAddresses);
    expect(server.search(client.search("security"))).toEqual([3n, 5n]);
  });

  it("returns no addresses and no results for an unseen keyword", () => {
    const client = makeClient();
    const server = new DianaServer();
    expect(client.searchAddresses("missing")).toEqual([]);
    expect(server.search(client.search("missing"))).toEqual([]);
  });

  it("restores serialized state and continues from the next update counter", () => {
    const original = makeClient();
    const server = new DianaServer();
    const first = original.prepareUpdate("database", 41n);
    server.insert(first.request);
    original.commitUpdate("database", first.expectedCount);

    const restored = DianaClient.restoreState(original.serializeState());
    expect(restored.getCount("database")).toBe(1);
    const second = restored.prepareUpdate("database", 42n);
    server.insert(second.request);
    restored.commitUpdate("database", second.expectedCount);

    expect(server.search(restored.search("database"))).toEqual([41n, 42n]);
    expect(restored.searchAddresses("database")).toHaveLength(2);
  });

  it("rejects malformed serialized state and duplicate counters", () => {
    expect(() => DianaClient.restoreState("{}")).toThrow();
    const state = JSON.parse(makeClient().serializeState());
    state.counters = [["cloud", 1], ["cloud", 2]];
    expect(() => DianaClient.restoreState(JSON.stringify(state))).toThrow(/invalid Diana counter/);
  });

  it("rejects duplicate update tokens at the server", () => {
    const client = makeClient();
    const server = new DianaServer();
    const pending = client.prepareUpdate("cloud", 1n);
    server.insert(pending.request);
    expect(() => server.insert(pending.request)).toThrow(/duplicate/);
  });
});

describe("Diana constrained RCPRF serialization", () => {
  it("preserves constrained range evaluations through serialization", () => {
    const rootKey = new Uint8Array(32).fill(0x5a);
    const constrained = createConstrainedRcpRf(rootKey, 0n, 12n);
    const restored = deserializeConstrained(serializeConstrained(constrained));
    const before = evaluateConstrainedRange(constrained, 0n, 12n);
    const after = evaluateConstrainedRange(restored, 0n, 12n);
    expect(after.map(({ leaf, value }) => [leaf, bytesToHex(value)]))
      .toEqual(before.map(({ leaf, value }) => [leaf, bytesToHex(value)]));
  });

  it("does not evaluate leaves outside the constrained range", () => {
    const constrained = createConstrainedRcpRf(keyA, 2n, 5n);
    expect(() => evaluateConstrainedRange(constrained, 0n, 1n)).toThrow();
    expect(() => evaluateConstrainedRange(constrained, 2n, 6n)).toThrow();
  });

  it("rejects truncated or malformed serialized constrained keys", () => {
    const constrained = createConstrainedRcpRf(keyA, 0n, 3n);
    const serialized = serializeConstrained(constrained);
    expect(() => deserializeConstrained(serialized.slice(0, 3))).toThrow();
    const malformed = serialized.slice();
    malformed[0] = 1;
    expect(() => deserializeConstrained(malformed)).toThrow();
  });
});
