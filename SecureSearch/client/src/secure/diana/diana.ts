import {
  assertLength,
  bytesToHex,
  hexToBytes,
  uint64FromLittleEndian,
  uint64ToLittleEndian,
  xorBytes,
} from "./bytes.js";
import {
  blake2b512,
  chacha20Prg,
  hmacBlake2b,
  KEY_BYTES,
} from "./primitives.js";
import {
  assertConstrainedPrefix,
  ConstrainedRcpRf,
  createConstrainedRcpRf,
  deserializeConstrained,
  DIANA_MAX_LEAF,
  DIANA_TREE_HEIGHT,
  evaluateConstrained,
  evaluateConstrainedRange,
  serializeConstrained,
} from "./rcprf.js";


export const KEYWORD_INDEX_BYTES = 16;
export const UPDATE_TOKEN_BYTES = 16;
export const DOCUMENT_INDEX_BYTES = 8;
export const KEYWORD_TOKEN_BYTES = 32;
export const MAX_ADD_COUNT = 0xffff_ffff;

export interface DianaUpdateRequest {
  readonly token: Uint8Array;
  readonly index: Uint8Array;
}

export interface DianaSearchToken {
  readonly keywordToken: Uint8Array;
  readonly constrainedKey: Uint8Array | null;
  readonly addCount: number;
}

interface SerializedClientState {
  readonly version: 1;
  readonly derivationMasterKey: string;
  readonly keywordTokenMasterKey: string;
  readonly counters: ReadonlyArray<readonly [string, number]>;
}

function keywordIndex(keyword: string): Uint8Array {
  if (typeof keyword !== "string" || keyword.length === 0) {
    throw new TypeError("keyword must be a non-empty string");
  }
  return blake2b512(new TextEncoder().encode(keyword)).slice(
    0,
    KEYWORD_INDEX_BYTES,
  );
}

function updateTokenAndMask(
  leafKey: Uint8Array,
): { token: Uint8Array; mask: Uint8Array } {
  const stream = chacha20Prg(
    leafKey,
    0,
    UPDATE_TOKEN_BYTES + DOCUMENT_INDEX_BYTES,
  );
  return {
    token: stream.slice(0, UPDATE_TOKEN_BYTES),
    mask: stream.slice(UPDATE_TOKEN_BYTES),
  };
}

function validateCount(count: number): void {
  if (
    !Number.isInteger(count) ||
    count < 0 ||
    count > MAX_ADD_COUNT
  ) {
    throw new RangeError("keyword counter must be an unsigned 32-bit count");
  }
  if (BigInt(count) - 1n > DIANA_MAX_LEAF) {
    throw new RangeError("keyword counter exceeds the Diana RCPRF tree");
  }
}

function secureRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}\n\nexport class DianaClient {
  readonly #derivationMasterKey: Uint8Array;
  readonly #keywordTokenMasterKey: Uint8Array;
  readonly #counters = new Map<string, number>();

  private constructor(
    derivationMasterKey: Uint8Array,
    keywordTokenMasterKey: Uint8Array,
    counters: ReadonlyMap<string, number> = new Map(),
  ) {
    assertLength(derivationMasterKey, KEY_BYTES, "derivation master key");
    assertLength(keywordTokenMasterKey, KEY_BYTES, "keyword token master key");
    this.#derivationMasterKey = derivationMasterKey.slice();
    this.#keywordTokenMasterKey = keywordTokenMasterKey.slice();
    for (const [keyword, count] of counters) {
      if (!keyword) {
        throw new TypeError("restored keyword must not be empty");
      }
      validateCount(count);
      this.#counters.set(keyword, count);
    }
  }

  static setup(): DianaClient {
    return new DianaClient(
      secureRandomBytes(KEY_BYTES),
      secureRandomBytes(KEY_BYTES),
    );
  }

  static fromMasterKeys(
    derivationMasterKey: Uint8Array,
    keywordTokenMasterKey: Uint8Array,
  ): DianaClient {
    return new DianaClient(derivationMasterKey, keywordTokenMasterKey);
  }

  static restoreState(serialized: string): DianaClient {
    const state = JSON.parse(serialized) as Partial<SerializedClientState>;
    if (
      state.version !== 1 ||
      typeof state.derivationMasterKey !== "string" ||
      typeof state.keywordTokenMasterKey !== "string" ||
      !Array.isArray(state.counters)
    ) {
      throw new TypeError("invalid Diana client state");
    }
    const counters = new Map<string, number>();
    for (const entry of state.counters) {
      if (
        !Array.isArray(entry) ||
        entry.length !== 2 ||
        typeof entry[0] !== "string" ||
        entry[0].length === 0 ||
        typeof entry[1] !== "number" ||
        counters.has(entry[0])
      ) {
        throw new TypeError("invalid Diana counter value");
      }
      counters.set(entry[0], entry[1]);
    }
    return new DianaClient(
      hexToBytes(state.derivationMasterKey, "derivation master key"),
      hexToBytes(state.keywordTokenMasterKey, "keyword token master key"),
      counters,
    );
  }

  getCount(keyword: string): number {
    if (typeof keyword !== "string" || keyword.length === 0) {
      throw new TypeError("keyword must be a non-empty string");
    }
    return this.#counters.get(keyword) ?? 0;
  }

  prepareUpdate(keyword: string, documentIndex: bigint): { request: DianaUpdateRequest; expectedCount: number } {
    const count = this.getCount(keyword);
    if (count >= MAX_ADD_COUNT) {
      throw new RangeError("Diana uint32 add_count limit reached");
    }
    const leaf = BigInt(count);
    if (leaf > DIANA_MAX_LEAF) {
      throw new RangeError("Diana RCPRF tree limit reached");
    }

    const index = keywordIndex(keyword);
    const rootKey = hmacBlake2b(
      this.#derivationMasterKey,
      index,
      KEY_BYTES,
    );
    const leafKey = evaluateConstrained(
      createConstrainedRcpRf(rootKey, leaf, leaf),
      leaf,
    );
    const { token, mask } = updateTokenAndMask(leafKey);
    const maskedIndex = xorBytes(uint64ToLittleEndian(documentIndex), mask);

    return { request: { token, index: maskedIndex }, expectedCount: count };
  }

  /** Commit a prepared update only after the server durably acknowledges it. */
  commitUpdate(keyword: string, expectedCount: number): void {
    if (this.getCount(keyword) !== expectedCount) {
      throw new Error("Diana state changed while an update was pending");
    }
    if (expectedCount >= MAX_ADD_COUNT) throw new RangeError("Diana uint32 add_count limit reached");
    this.#counters.set(keyword, expectedCount + 1);
  }

  /** Convenience for prototype compatibility. Production clients should use prepareUpdate/commitUpdate. */
  update(keyword: string, documentIndex: bigint): DianaUpdateRequest {
    const prepared = this.prepareUpdate(keyword, documentIndex);
    this.commitUpdate(keyword, prepared.expectedCount);
    return prepared.request;
  }

  search(keyword: string): DianaSearchToken {
    const count = this.getCount(keyword);
    validateCount(count);
    if (count === 0) {
      return {
        keywordToken: new Uint8Array(KEYWORD_TOKEN_BYTES),
        constrainedKey: null,
        addCount: 0,
      };
    }

    const index = keywordIndex(keyword);
    const rootKey = hmacBlake2b(
      this.#derivationMasterKey,
      index,
      KEY_BYTES,
    );
    const constrained = createConstrainedRcpRf(
      rootKey,
      0n,
      BigInt(count - 1),
    );
    return {
      keywordToken: hmacBlake2b(
        this.#keywordTokenMasterKey,
        index,
        KEYWORD_TOKEN_BYTES,
      ),
      constrainedKey: serializeConstrained(constrained),
      addCount: count,
    };
  }

  serializeState(): string {
    const counters = Array.from(this.#counters.entries());
    const state: SerializedClientState = {
      version: 1,
      derivationMasterKey: bytesToHex(this.#derivationMasterKey),
      keywordTokenMasterKey: bytesToHex(this.#keywordTokenMasterKey),
      counters,
    };
    return JSON.stringify(state);
  }
}

export interface EvaluatedSearchLeaf {
  readonly leaf: bigint;
  readonly value: Uint8Array;
}

export class DianaServer {
  readonly #entries = new Map<string, Uint8Array>();

  insert(request: DianaUpdateRequest): void {
    assertLength(request.token, UPDATE_TOKEN_BYTES, "update token");
    assertLength(request.index, DOCUMENT_INDEX_BYTES, "masked document index");
    const address = bytesToHex(request.token);
    if (this.#entries.has(address)) {
      throw new Error("duplicate Diana update token");
    }
    this.#entries.set(address, request.index.slice());
  }

  evaluateSearchLeaves(token: DianaSearchToken): EvaluatedSearchLeaf[] {
    assertLength(token.keywordToken, KEYWORD_TOKEN_BYTES, "keyword token");
    if (!Number.isInteger(token.addCount) || token.addCount < 0) {
      throw new RangeError("invalid Diana add_count");
    }
    if (token.addCount > MAX_ADD_COUNT) {
      throw new RangeError("Diana add_count exceeds uint32");
    }
    if (token.addCount === 0) {
      if (token.constrainedKey !== null) {
        throw new RangeError("empty search must not include a constrained key");
      }
      return [];
    }
    if (token.constrainedKey === null) {
      throw new RangeError("non-empty search requires a constrained key");
    }

    const constrained = deserializeConstrained(token.constrainedKey);
    assertConstrainedPrefix(constrained, token.addCount);
    return evaluateConstrainedRange(
      constrained,
      0n,
      BigInt(token.addCount - 1),
    );
  }

  search(token: DianaSearchToken): bigint[] {
    const leaves = this.evaluateSearchLeaves(token);
    const results: bigint[] = [];
    for (const { value } of leaves) {
      const { token: address, mask } = updateTokenAndMask(value);
      const maskedIndex = this.#entries.get(bytesToHex(address));
      if (maskedIndex === undefined) {
        throw new Error(
          `missing Diana update entry for token ${bytesToHex(address)}`,
        );
      }
      results.push(uint64FromLittleEndian(xorBytes(maskedIndex, mask)));
    }
    return results;
  }
}
