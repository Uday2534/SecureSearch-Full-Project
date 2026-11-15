import { Router } from "express";
import { createHash } from "node:crypto";
import { z } from "zod";
import mongoose from "mongoose";
import { authenticate } from "../middleware/auth.js";
import { SecureRecord } from "../models/SecureRecord.js";

const router = Router();
const addressSchema = z.string().regex(/^[0-9a-f]{32,64}$/i);
const recordSchema = z.object({
  namespace: z.enum(["index", "document"]),
  address: addressSchema,
  value: z.string().min(1).max(12_000_000),
  revision: z.number().int().positive(),
  batchId: z.string().min(8).max(80).regex(/^[a-zA-Z0-9_-]+$/),
}).strict();

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Stores only client-encrypted/opaque values. This route does not perform
 * keyword tokenization, decryption, or search. It is not yet Merkle-backed.
 */
router.post("/records", authenticate, async (req, res, next) => {
  try {
    const parsed = recordSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: "Invalid opaque record", issues: parsed.error.issues });
    const userId = req.userId!;
    if (!mongoose.isValidObjectId(userId)) return res.status(401).json({ message: "Invalid account" });

    const { namespace, address, value, revision, batchId } = parsed.data;
    const valueDigest = digest(value);
    // Revisions are monotonic per address. A stale client cannot silently
    // overwrite a newer opaque record with an older version.
    let record = await SecureRecord.findOneAndUpdate(
      {
        owner: userId, namespace, address,
        $or: [{ revision: { $lt: revision } }, { revision: { $exists: false } }],
      },
      { $set: { value, valueDigest, revision, batchId } },
      { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true },
    ).select("namespace address value valueDigest revision batchId updatedAt").lean();

    if (!record) {
      const current = await SecureRecord.findOne({ owner: userId, namespace, address })
        .select("namespace address value valueDigest revision batchId updatedAt").lean();
      if (current && current.revision === revision && current.valueDigest === valueDigest) {
        record = current;
      } else {
        return res.status(409).json({ message: "Stale or conflicting record revision", currentRevision: current?.revision ?? null });
      }
    }

    return res.status(200).json({ record });
  } catch (error) { return next(error); }
});

/** Fetch one opaque address; callers must verify returned data against a trusted commitment. */
router.get("/records/:namespace/:address", authenticate, async (req, res, next) => {
  try {
    const namespace = z.enum(["index", "document"]).safeParse(req.params.namespace);
    const address = addressSchema.safeParse(req.params.address);
    if (!namespace.success || !address.success) return res.status(400).json({ message: "Invalid record address" });

    const record = await SecureRecord.findOne({
      owner: req.userId, namespace: namespace.data, address: address.data,
    }).select("namespace address value valueDigest revision batchId updatedAt").lean();

    if (!record) return res.status(404).json({ message: "Record not found" });
    if (digest(record.value) !== record.valueDigest) {
      return res.status(409).json({ message: "Stored record digest mismatch" });
    }
    return res.json({ record });
  } catch (error) { return next(error); }
});

/** Lists the user's opaque records for client-side audit/reconciliation. */
router.get("/records", authenticate, async (req, res, next) => {
  try {
    const parsed = z.object({
      namespace: z.enum(["index", "document"]).optional(),
      after: z.string().optional(),
      limit: z.coerce.number().int().min(1).max(500).default(100),
    }).safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ message: "Invalid pagination" });

    const filter: Record<string, unknown> = { owner: req.userId };
    if (parsed.data.namespace) filter.namespace = parsed.data.namespace;
    if (parsed.data.after) filter.address = { $gt: parsed.data.after };

    const records = await SecureRecord.find(filter)
      .sort({ address: 1 }).limit(parsed.data.limit)
      .select("namespace address value valueDigest revision batchId updatedAt").lean();

    const next = records.length === parsed.data.limit ? records[records.length - 1].address : null;
    return res.json({ records, next });
  } catch (error) { return next(error); }
});


function hashNode(left: Buffer, right: Buffer): Buffer {
  return createHash("sha256").update(Buffer.concat([Buffer.from([1]), left, right])).digest();
}
function hashLeaf(key: string, valueDigest: string): Buffer {
  return createHash("sha256").update(Buffer.concat([
    Buffer.from([0]), Buffer.from(key, "utf8"), Buffer.from([0]), Buffer.from(valueDigest, "hex"),
  ])).digest();
}
function buildMerkleProof(leaves: Array<{ key: string; valueDigest: string }>, targetKey: string) {
  let level = leaves.map((leaf) => hashLeaf(leaf.key, leaf.valueDigest));
  let index = leaves.findIndex((leaf) => leaf.key === targetKey);
  if (index < 0) return null;
  const leafIndex = index;
  const siblings: Array<{ hash: string; side: "left" | "right" }> = [];
  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? Math.min(index + 1, level.length - 1) : index - 1;
    siblings.push({ hash: level[siblingIndex]!.toString("hex"), side: index % 2 === 0 ? "right" : "left" });
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(hashNode(level[i]!, level[i + 1] ?? level[i]!));
    }
    index = Math.floor(index / 2);
    level = next;
  }
  return { leafIndex, leafCount: leaves.length, siblings, root: level[0]!.toString("hex") };
}

/**
 * Returns requested opaque index records with inclusion proofs over the
 * complete owner tree. Client compares the root to its locally trusted root
 * and independently checks that every expected Diana address was returned.
 */
router.post("/search-proof", authenticate, async (req, res, next) => {
  try {
    const parsed = z.object({
      entries: z.array(z.object({
        namespace: z.enum(["index", "document"]),
        address: addressSchema,
      }).strict()).min(1).max(5000),
    }).strict().safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ message: "Invalid proof address set" });
    const requestedKeys = parsed.data.entries.map((entry) => `${entry.namespace}:${entry.address}`);
    if (new Set(requestedKeys).size !== requestedKeys.length) {
      return res.status(400).json({ message: "Duplicate proof addresses are not allowed" });
    }

    const stored = await SecureRecord.find({ owner: req.userId })
      .select("namespace address value valueDigest revision batchId updatedAt")
      .sort({ namespace: 1, address: 1 }).limit(50000).lean();
    if (stored.length >= 50000) {
      return res.status(413).json({ message: "Secure index exceeds proof endpoint limit; paginate or compact the index." });
    }
    const leaves = stored.map((record) => ({
      key: `${record.namespace}:${record.address}`,
      valueDigest: record.valueDigest,
    })).sort((a, b) => a.key.localeCompare(b.key));

    const records = parsed.data.entries.map(({ namespace, address }) => {
      const record = stored.find((item) => item.namespace === namespace && item.address === address);
      if (!record) return null;
      const key = `${namespace}:${address}`;
      const proof = buildMerkleProof(leaves, key);
      return proof ? { record, proof: { leafIndex: proof.leafIndex, leafCount: proof.leafCount, siblings: proof.siblings } } : null;
    }).filter((item): item is NonNullable<typeof item> => item !== null);

    const root = leaves.length === 0
      ? createHash("sha256").update(Buffer.alloc(0)).digest("hex")
      : buildMerkleProof(leaves, leaves[0]!.key)!.root;
    return res.json({ root, records });
  } catch (error) { return next(error); }
});

export default router;
