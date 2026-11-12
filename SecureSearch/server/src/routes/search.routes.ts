import { Router } from "express";
import { z } from "zod";
import { authenticate } from "../middleware/auth.js";
import { Document } from "../models/Document.js";
import { keywordToken, decrypt } from "../services/crypto.service.js";
import { tokenize, makeSnippet } from "../services/tokenizer.service.js";
const router = Router();
router.use(authenticate);
router.post("/", async (req, res, next) => {
  try {
    const { query } = z.object({ query: z.string().trim().min(1).max(500) }).parse(req.body);
    const terms = tokenize(query);
    if (!terms.length) return res.status(400).json({ message: "Enter at least one searchable word" });
    const tokens = terms.map(t => keywordToken(t, req.userId!));
    const docs = await Document.find({ owner: req.userId, tokens: { $all: tokens } }).sort({ createdAt: -1 }).limit(100);
    const results = docs.map(doc => {
      const text = decrypt(doc.encryptedText, req.userId!, "extracted-text").toString("utf8");
      return { id: doc.id, name: doc.originalName, size: doc.size, wordCount: doc.wordCount, createdAt: doc.createdAt, snippet: makeSnippet(text, terms) };
    });
    res.json({ query, terms, count: results.length, results });
  } catch (e: any) { if (e?.name === "ZodError") return res.status(400).json({ message: e.issues[0].message }); next(e); }
});
export default router;
