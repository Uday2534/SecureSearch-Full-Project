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
  value: z.string().min(1).max(2_000_000),
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

export default router;
