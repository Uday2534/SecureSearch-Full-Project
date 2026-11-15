import { bytesToHex, secureTextEncoder } from "../crypto";
import { sealVaultState } from "../crypto";
import { saveEncryptedVault } from "../vaultStorage";
import { putSecureRecord } from "../api";
import { DianaClient } from "./diana";

export interface SecureVaultState {
  version: 1;
  dianaState: string;
  nextDocumentIndex: string;
  documentKeys: Record<string, string>;
}

export function normalizeSecureKeywords(text: string): string[] {
  return Array.from(new Set(
    text.normalize("NFKC")
      .toLocaleLowerCase("und")
      .match(/[\p{L}\p{N}]+/gu) ?? [],
  ));
}

export function createSecureVaultState(): { client: DianaClient; state: SecureVaultState } {
  const client = DianaClient.setup();
  return {
    client,
    state: { version: 1, dianaState: client.serializeState(), nextDocumentIndex: "1", documentKeys: {} },
  };
}

/**
 * Adds one document's keyword postings. For each posting the counter is
 * advanced only after the server acknowledges an idempotent opaque write.
 * The encrypted vault is saved after each acknowledgement, so a refresh
 * cannot silently reuse a committed Diana leaf.
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
    const request = prepared.request;
    const address = bytesToHex(request.token);
    const value = bytesToBase64(request.index);
    const batchId = crypto.randomUUID();

    await putSecureRecord({
      namespace: "index",
      address,
      value,
      revision: prepared.expectedCount + 1,
      batchId,
    });

    args.client.commitUpdate(keyword, prepared.expectedCount);
    const nextState: SecureVaultState = {
      ...args.state,
      dianaState: args.client.serializeState(),
    };
    await saveEncryptedVault(await sealVaultState(nextState, args.passphrase));
    args.state = nextState;
    completed += 1;
    args.onProgress?.(completed, uniqueKeywords.length);
  }

  return args.state;
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
