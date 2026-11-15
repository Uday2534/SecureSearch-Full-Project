import mongoose, { Schema, Types } from "mongoose";

/**
 * Opaque records for the v2 client-side encryption path.
 * This collection deliberately has no plaintext keyword/document-name fields.
 */
export interface ISecureRecord {
  owner: Types.ObjectId;
  namespace: "index" | "document";
  address: string;
  value: string;
  valueDigest: string;
  revision: number;
  batchId: string;
  createdAt?: Date;
  updatedAt?: Date;
}

const secureRecordSchema = new Schema<ISecureRecord>({
  owner: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
  namespace: { type: String, enum: ["index", "document"], required: true },
  address: { type: String, required: true, match: /^[0-9a-f]{32,64}$/i },
  value: { type: String, required: true, maxlength: 12_000_000 },
  valueDigest: { type: String, required: true, match: /^[0-9a-f]{64}$/i },
  revision: { type: Number, required: true, min: 1 },
  batchId: { type: String, required: true, maxlength: 80 },
}, { timestamps: true });

secureRecordSchema.index({ owner: 1, namespace: 1, address: 1 }, { unique: true });
secureRecordSchema.index({ owner: 1, batchId: 1 });

export const SecureRecord = mongoose.model<ISecureRecord>("SecureRecord", secureRecordSchema);
