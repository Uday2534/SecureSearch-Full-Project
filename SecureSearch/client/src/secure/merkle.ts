/**
 * SHA-256 Merkle inclusion-proof verification.
 *
 * Hash convention:
 *   leaf = SHA256(0x00 || UTF8(key) || 0x00 || valueDigest)
 *   node = SHA256(0x01 || left || right)
 *
 * The server must use exactly the same domain separation and byte encoding.
 * Inclusion proofs establish membership only; completeness requires the client
 * to independently derive the expected address set and compare it to results.
 */

import { hexToBytes, sha256 } from "./crypto";

export interface MerkleProof {
  leafIndex: number;
  leafCount: number;
  siblings: Array<{ hash: string; side: "left" | "right" }>;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export async function merkleLeafHash(key: string, valueDigestHex: string): Promise<Uint8Array> {
  return sha256(concat(
    new Uint8Array([0]),
    new TextEncoder().encode(key),
    new Uint8Array([0]),
    hexToBytes(valueDigestHex),
  ));
}

export async function verifyMerkleInclusion(
  key: string,
  valueDigestHex: string,
  proof: MerkleProof,
  expectedRootHex: string,
): Promise<boolean> {
  if (
    !Number.isSafeInteger(proof.leafIndex) ||
    !Number.isSafeInteger(proof.leafCount) ||
    proof.leafCount < 1 ||
    proof.leafIndex < 0 ||
    proof.leafIndex >= proof.leafCount
  ) return false;

  let current = await merkleLeafHash(key, valueDigestHex);
  let index = proof.leafIndex;
  let width = proof.leafCount;

  for (const sibling of proof.siblings) {
    const siblingBytes = hexToBytes(sibling.hash);
    if (siblingBytes.length !== 32) return false;
    const expectedSide = index % 2 === 0 ? "right" : "left";
    if (sibling.side !== expectedSide) return false;

    current = sibling.side === "left"
      ? await sha256(concat(new Uint8Array([1]), siblingBytes, current))
      : await sha256(concat(new Uint8Array([1]), current, siblingBytes));

    index = Math.floor(index / 2);
    width = Math.ceil(width / 2);
  }

  return width === 1 && bytesToLowerHex(current) === expectedRootHex.toLowerCase();
}

function bytesToLowerHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export interface MerkleLeaf {
  key: string;
  valueDigest: string;
}

/** Computes the canonical root for a sorted set of authenticated map leaves. */
export async function computeMerkleRoot(leaves: MerkleLeaf[]): Promise<string> {
  if (leaves.length === 0) return bytesToLowerHex(await sha256(new Uint8Array()));
  const sorted = [...leaves].sort((a, b) => a.key.localeCompare(b.key));
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i - 1]!.key === sorted[i]!.key) throw new Error("Duplicate Merkle leaf key");
  }
  let level = await Promise.all(sorted.map((leaf) => merkleLeafHash(leaf.key, leaf.valueDigest)));
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const right = level[i + 1] ?? level[i]!;
      next.push(await sha256(concat(new Uint8Array([1]), level[i]!, right)));
    }
    level = next;
  }
  return bytesToLowerHex(level[0]!);
}
