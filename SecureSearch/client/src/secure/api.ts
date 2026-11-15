import { api } from "../api";

export type SecureNamespace = "index" | "document";

export interface SecureRecordInput {
  namespace: SecureNamespace;
  address: string;
  /** Client-encrypted or otherwise opaque payload, base64-encoded by caller. */
  value: string;
  revision: number;
  batchId: string;
}

export interface SecureRecord {
  namespace: SecureNamespace;
  address: string;
  value: string;
  valueDigest: string;
  revision: number;
  batchId: string;
  updatedAt: string;
}

export async function putSecureRecord(input: SecureRecordInput): Promise<SecureRecord> {
  const response = await api.post<{ record: SecureRecord }>("/secure/records", input);
  return response.data.record;
}

export async function getSecureRecord(
  namespace: SecureNamespace,
  address: string,
): Promise<SecureRecord> {
  const response = await api.get<{ record: SecureRecord }>(
    `/secure/records/${namespace}/${encodeURIComponent(address)}`,
  );
  return response.data.record;
}

export async function listSecureRecords(options: {
  namespace?: SecureNamespace;
  after?: string;
  limit?: number;
} = {}): Promise<{ records: SecureRecord[]; next: string | null }> {
  const response = await api.get<{ records: SecureRecord[]; next: string | null }>(
    "/secure/records",
    { params: options },
  );
  return response.data;
}

import type { MerkleProof } from "./merkle";

export interface ProvenSecureRecord {
  record: SecureRecord;
  proof: MerkleProof;
}

export async function fetchSecureRecordProofs(entries: Array<{
  namespace: SecureNamespace;
  address: string;
}>): Promise<{ root: string; records: ProvenSecureRecord[] }> {
  const response = await api.post<{ root: string; records: ProvenSecureRecord[] }>(
    "/secure/search-proof",
    { entries },
  );
  return response.data;
}

export async function putSecureRecords(inputs: SecureRecordInput[]): Promise<SecureRecord[]> {
  const response = await api.post<{ records: SecureRecord[] }>("/secure/records/batch", { records: inputs });
  return response.data.records;
}
