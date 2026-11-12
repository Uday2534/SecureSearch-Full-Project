import { Router } from "express";
import multer from "multer";
import path from "node:path";
import { authenticate } from "../middleware/auth.js";
import { env } from "../config/env.js";
import { extractText } from "../services/extractor.service.js";
import { encrypt, keywordToken, decrypt } from "../services/crypto.service.js";
import { tokenize } from "../services/tokenizer.service.js";
import { Document } from "../models/Document.js";
const router = Router();
const allowed = new Set([".pdf",".docx",".doc",".xlsx",".xls",".pptx",".ppt",".csv",".txt",".md",".markdown",".html",".htm",".xml",".json",".rtf",".odt",".ods",".odp",".log"]);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: env.MAX_FILE_SIZE_MB * 1024 * 1024 } });
router.use(authenticate);
router.post("/", upload.single("file"), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ message: "Choose a file to upload" });
    const extension = path.extname(req.file.originalname).toLowerCase();
    if (!allowed.has(extension)) return res.status(415).json({ message: `Unsupported file type: ${extension}` });
    const text = await extractText(req.file.buffer, req.file.originalname);
    const words = tokenize(text);
    if (!words.length) return res.status(422).json({ message: "No searchable words found in this file" });
    const userId = req.userId!;
    const doc = await Document.create({
      owner: userId, originalName: path.basename(req.file.originalname), mimeType: req.file.mimetype || "application/octet-stream",
      extension, size: req.file.size, encryptedFile: encrypt(req.file.buffer, userId, "original-file"),
      encryptedText: encrypt(text, userId, "extracted-text"), tokens: words.map(w => keywordToken(w, userId)), wordCount: words.length
    });
    res.status(201).json({ document: { id: doc.id, name: doc.originalName, size: doc.size, wordCount: doc.wordCount, createdAt: doc.createdAt } });
  } catch (e: any) { if (e.code === "LIMIT_FILE_SIZE") return res.status(413).json({ message: `File exceeds ${env.MAX_FILE_SIZE_MB} MB limit` }); next(e); }
});
router.get("/", async (req, res, next) => {
  try {
    const docs = await Document.find({ owner: req.userId }).select("-encryptedFile -encryptedText -tokens").sort({ createdAt: -1 }).lean();
    res.json({ documents: docs.map(d => ({ id: d._id, name: d.originalName, size: d.size, extension: d.extension, wordCount: d.wordCount, createdAt: d.createdAt })) });
  } catch (e) { next(e); }
});
router.get("/:id/download", async (req, res, next) => {
  try {
    const doc = await Document.findOne({ _id: req.params.id, owner: req.userId });
    if (!doc) return res.status(404).json({ message: "Document not found" });
    const bytes = decrypt(doc.encryptedFile, req.userId!, "original-file");
    res.setHeader("Content-Type", doc.mimeType);
    res.setHeader("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(doc.originalName)}`);
    res.send(bytes);
  } catch (e) { next(e); }
});
router.delete("/:id", async (req, res, next) => {
  try {
    const result = await Document.deleteOne({ _id: req.params.id, owner: req.userId });
    if (!result.deletedCount) return res.status(404).json({ message: "Document not found" });
    res.json({ message: "Document deleted" });
  } catch (e) { next(e); }
});
export default router;
