import {
  createDocumentKey, encryptFileBytes, exportDocumentKey, importDocumentKey,
  decryptFileBytes, sha256, bytesToHex, secureTextEncoder,
} from "../crypto";
import { putSecureRecord, fetchSecureRecordProofs } from "../api";
import { saveEncryptedVault } from "../vaultStorage";
import { sealVaultState } from "../crypto";
import { computeMerkleRoot, verifyMerkleInclusion } from "../merkle";
import {
  addDocumentPostings, base64ToBytes, bytesToBase64,
  normalizeSecureKeywords, searchDianaKeyword, type SecureVaultState,
} from "./workflow";
import { DianaClient } from "./diana";

const MAX_SECURE_FILE_BYTES = 5 * 1024 * 1024;
const SUPPORTED = new Set(["txt", "csv", "md", "markdown", "json", "html", "htm", "xml", "log"]);

function extension(name: string): string {
  return name.split(".").pop()?.toLowerCase() ?? "";
}

async function extractSearchableText(file: File): Promise<string> {
  const ext = extension(file.name);
  if (!SUPPORTED.has(ext)) {
    throw new Error("Secure v2 currently supports TXT, CSV, Markdown, JSON, HTML, XML and LOG files. Use the legacy upload for other formats.");
  }
  const text = await file.text();
  if (ext === "html" || ext === "htm" || ext === "xml") {
    return text.replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/&amp;/gi, "&");
  }
  if (ext === "json") {
    try { return JSON.stringify(JSON.parse(text)); }
    catch { throw new Error("The selected JSON file is not valid JSON."); }
  }
  return text;
}

function randomAddress(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return bytesToHex(bytes);
}

async function persist(state: SecureVaultState, passphrase: string): Promise<void> {
  await saveEncryptedVault(await sealVaultState(state, passphrase));
}

export async function uploadSecureDocument(args: {
  file: File;
  client: DianaClient;
  state: SecureVaultState;
  passphrase: string;
  onProgress?: (done: number, total: number) => void;
}): Promise<SecureVaultState> {
  if (args.file.size === 0) throw new Error("The selected file is empty.");
  if (args.file.size > MAX_SECURE_FILE_BYTES) throw new Error("Secure v2 currently limits files to 5 MB.");
  const searchableText = await extractSearchableText(args.file);
  const keywords = normalizeSecureKeywords(searchableText);
  if (keywords.length === 0) throw new Error("No searchable words were found in this file.");

  const documentIndex = BigInt(args.state.nextDocumentIndex);
  if (documentIndex < 1n || documentIndex > 0xffff_ffff_ffff_ffffn) {
    throw new Error("Document index limit reached.");
  }

  const key = await createDocumentKey();
  const payload = new File([
    JSON.stringify({
      name: args.file.name,
      mimeType: args.file.type || "application/octet-stream",
      contentBase64: bytesToBase64(new Uint8Array(await args.file.arrayBuffer())),
    }),
  ], "secure-document.json", { type: "application/json" });
  const encrypted = await encryptFileBytes(payload, key);
  const address = randomAddress();
  const value = JSON.stringify({
    iv: encrypted.iv,
    ciphertext: bytesToBase64(new Uint8Array(encrypted.ciphertext)),
  });

  const expectedDigest = bytesToHex(await sha256(secureTextEncoder.encode(value)));
  const stored = await putSecureRecord({
    namespace: "document",
    address,
    value,
    revision: 1,
    batchId: crypto.randomUUID(),
  });

  if (stored.valueDigest.toLowerCase() !== expectedDigest) {
    throw new Error("Server acknowledged an unexpected encrypted document digest.");
  }

  const trustedLeaves = {
    ...args.state.trustedLeaves,
    [`document:${address}`]: stored.valueDigest,
  };
  const documentKeys = {
    ...args.state.documentKeys,
    [documentIndex.toString()]: JSON.stringify({
      address,
      key: await exportDocumentKey(key),
    }),
  };
  let nextState: SecureVaultState = {
    ...args.state,
    nextDocumentIndex: (documentIndex + 1n).toString(),
    documentKeys,
    trustedLeaves,
    trustedRoot: await computeMerkleRoot(
      Object.entries(trustedLeaves).map(([leafKey, valueDigest]) => ({ key: leafKey, valueDigest })),
    ),
  };
  await persist(nextState, args.passphrase);

  nextState = await addDocumentPostings({
    client: args.client,
    keywords,
    documentIndex,
    passphrase: args.passphrase,
    state: nextState,
    onProgress: args.onProgress,
  });
  return nextState;
}

export interface DecryptedSecureDocument {
  name: string;
  mimeType: string;
  blob: Blob;
  documentIndex: string;
}

export async function searchAndDecryptDocuments(args: {
  query: string;
  client: DianaClient;
  state: SecureVaultState;
}): Promise<DecryptedSecureDocument[]> {
  const keywords = normalizeSecureKeywords(args.query);
  if (keywords.length === 0) throw new Error("Enter at least one search keyword.");

  const postingSets = await Promise.all(keywords.map((keyword) =>
    searchDianaKeyword({ client: args.client, keyword, state: args.state }),
  ));
  const common = new Set(postingSets[0]!.map(String));
  for (const posting of postingSets.slice(1)) {
    const current = new Set(posting.map(String));
    for (const id of common) if (!current.has(id)) common.delete(id);
  }

  const results: DecryptedSecureDocument[] = [];
  for (const index of common) {
    const keyEntry = args.state.documentKeys[index];
    if (!keyEntry) throw new Error(`Vault is missing the key for document index ${index}.`);
    const metadata = JSON.parse(keyEntry) as { address: string; key: string };
    const response = await fetchSecureRecordProofs([{ namespace: "document", address: metadata.address }]);
    if (response.root.toLowerCase() !== args.state.trustedRoot.toLowerCase()) {
      throw new Error("Secure index root mismatch while retrieving a document.");
    }
    if (response.records.length !== 1) throw new Error("Document record is missing from the authenticated map.");
    const item = response.records[0]!;
    const valid = await verifyMerkleInclusion(
      `document:${metadata.address}`,
      item.record.valueDigest,
      item.proof,
      response.root,
    );
    if (!valid) throw new Error("Document Merkle proof verification failed.");

    const envelope = JSON.parse(item.record.value) as { iv: string; ciphertext: string };
    const key = await importDocumentKey(metadata.key);
    const encryptedBytes = base64ToBytes(envelope.ciphertext);
    const encryptedBuffer = encryptedBytes.buffer.slice(
      encryptedBytes.byteOffset,
      encryptedBytes.byteOffset + encryptedBytes.byteLength,
    ) as ArrayBuffer;
    const plaintext = await decryptFileBytes(encryptedBuffer, envelope.iv, key);
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as {
      name: string; mimeType: string; contentBase64: string;
    };
    const content = base64ToBytes(payload.contentBase64);
    results.push({
      name: payload.name,
      mimeType: payload.mimeType,
      blob: new Blob([content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength) as ArrayBuffer], { type: payload.mimeType }),
      documentIndex: index,
    });
  }
  return results;
}
