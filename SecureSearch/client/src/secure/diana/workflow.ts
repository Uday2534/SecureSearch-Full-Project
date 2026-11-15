import { bytesToHex, sha256, secureTextEncoder } from "../crypto";
import { sealVaultState } from "../crypto";
import { saveEncryptedVault } from "../vaultStorage";
import { putSecureRecord, fetchSecureRecordProofs } from "../api";
import { computeMerkleRoot, verifyMerkleInclusion } from "../merkle";
import { uint64FromLittleEndian, xorBytes } from "./bytes";
import { DianaClient } from "./diana";

export interface SecureVaultState {
  version: 1;
  dianaState: string;
  nextDocumentIndex: string;
  documentKeys: Record<string, string>;
  /** key -> SHA-256(value), retained locally to anchor the Merkle root */
  trustedLeaves: Record<string, string>;
  trustedRoot: string;
}

export function normalizeSecureKeywords(text: string): string[] {
  return Array.from(new Set(
    text.normalize("NFKC")
      .toLocaleLowerCase("und")
      .match(/[\\p{L}\\p{N}]+/gu) ?? [],
  ));
}

export async function createSecureVaultState(): Promise<{ client: DianaClient; state: SecureVaultState }> {
  const client = DianaClient.setup();
  const trustedLeaves: Record<string, string> = {};
  const trustedRoot = await computeMerkleRoot([]);
  return {
    client,
    state: {
      version: 1,
      dianaState: client.serializeState(),
      nextDocumentIndex: "1",
      documentKeys: {},
      trustedLeaves,
      trustedRoot,
    },
  };
}

async function persistState(state: SecureVaultState, passphrase: string): Promise<void> {
  await saveEncryptedVault(await sealVaultState(state, passphrase));
}

/**
 * Add Diana postings with per-keyword acknowledgement and durable encrypted
 * state. If a later posting fails, earlier acknowledged postings remain
 * committed and the saved counters/root describe that partial batch.
 */
export async function addDocumentPostings(args: {
  client: DianaClient;
  keywords: string[];
  documentIndex: bigint;
  passphrase: string;
  state: SecureVaultState;
  onProgress?: (completed: number, total: number) => void;
}): Promise<SecureVaultState> {
  const uniqueKeywords = Array.from(new Set(args.keywords));
  let completed = 0;

  for (const keyword of uniqueKeywords) {
    const prepared = args.client.prepareUpdate(keyword, args.documentIndex);
    const address = bytesToHex(prepared.request.token);
    const value = bytesToBase64(prepared.request.index);
    const batchId = crypto.randomUUID();

    const stored = await putSecureRecord({
      namespace: "index",
      address,
      value,
      revision: prepared.expectedCount + 1,
      batchId,
    });

    args.client.commitUpdate(keyword, prepared.expectedCount);
    const trustedLeaves = {
      ...args.state.trustedLeaves,
      [`index:${address}`]: stored.valueDigest,
    };
    const nextState: SecureVaultState = {
      ...args.state,
      dianaState: args.client.serializeState(),
      trustedLeaves,
      trustedRoot: await computeMerkleRoot(
        Object.entries(trustedLeaves).map(([key, valueDigest]) => ({ key, valueDigest })),
      ),
    };
    await persistState(nextState, args.passphrase);
    args.state = nextState;
    completed += 1;
    args.onProgress?.(completed, uniqueKeywords.length);
  }

  return args.state;
}

/**
 * Client derives every expected Diana address, asks the server for those
 * records, then verifies the trusted root, every inclusion proof, and exact
 * address-set equality before unmasking document indexes.
 */
export async function searchDianaKeyword(args: {
  client: DianaClient;
  keyword: string;
  state: SecureVaultState;
}): Promise<bigint[]> {
  const expected = args.client.searchAddresses(args.keyword);
  if (expected.length === 0) return [];

  const expectedAddresses = expected.map((item) => bytesToHex(item.address));
  const response = await fetchSecureRecordProofs(expectedAddresses.map((address) => ({ namespace: "index" as const, address })));
  if (response.root.toLowerCase() !== args.state.trustedRoot.toLowerCase()) {
    throw new Error("Secure index root mismatch: server state differs from the locally trusted index.");
  }

  const returned = new Map(response.records.map(({ record, proof }) => [record.address, { record, proof }] as const));
  if (returned.size !== expectedAddresses.length ||
      expectedAddresses.some((address) => !returned.has(address))) {
    throw new Error("Search completeness verification failed: one or more expected postings are missing or duplicated.");
  }

  const results: bigint[] = [];
  for (const item of expected) {
    const address = bytesToHex(item.address);
    const found = returned.get(address)!;
    const actualDigest = bytesToHex(await sha256(secureTextEncoder.encode(found.record.value)));
    if (actualDigest !== found.record.valueDigest.toLowerCase()) {
      throw new Error(`Opaque posting digest mismatch for ${address}.`);
    }
    const valid = await verifyMerkleInclusion(
      `index:${address}`,
      found.record.valueDigest,
      found.proof,
      response.root,
    );
    if (!valid) throw new Error(`Merkle proof verification failed for posting ${address}.`);

    const maskedIndex = base64ToBytes(found.record.value);
    if (maskedIndex.length !== 8) throw new Error("Invalid masked document index length.");
    results.push(uint64FromLittleEndian(xorBytes(maskedIndex, item.mask)));
  }
  return results;
}

export function encodeSearchToken(keyword: string, client: DianaClient): {
  keywordToken: string;
  constrainedKey: string | null;
  addCount: number;
} {
  const token = client.search(keyword);
  return {
    keywordToken: bytesToBase64(token.keywordToken),
    constrainedKey: token.constrainedKey ? bytesToBase64(token.constrainedKey) : null,
    addCount: token.addCount,
  };
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
