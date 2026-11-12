import mongoose, { Schema, Types } from "mongoose";
export interface IEncryptedPayload { iv: string; tag: string; data: string; }
export interface IDocument {
  owner: Types.ObjectId; originalName: string; mimeType: string; extension: string;
  size: number; encryptedFile: IEncryptedPayload; encryptedText: IEncryptedPayload;
  tokens: string[]; wordCount: number; createdAt?: Date; updatedAt?: Date;
}
const payloadSchema = new Schema<IEncryptedPayload>({
  iv: { type: String, required: true }, tag: { type: String, required: true },
  data: { type: String, required: true }
}, { _id: false });
const documentSchema = new Schema<IDocument>({
  owner: { type: Schema.Types.ObjectId, ref: "User", required: true, index: true },
  originalName: { type: String, required: true }, mimeType: { type: String, required: true },
  extension: { type: String, required: true }, size: { type: Number, required: true },
  encryptedFile: { type: payloadSchema, required: true },
  encryptedText: { type: payloadSchema, required: true },
  tokens: { type: [String], default: [], index: true }, wordCount: { type: Number, default: 0 }
}, { timestamps: true });
documentSchema.index({ owner: 1, tokens: 1 });
export const Document = mongoose.model<IDocument>("Document", documentSchema);
