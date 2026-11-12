import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { User } from "../models/User.js";
import { env } from "../config/env.js";
import { authenticate } from "../middleware/auth.js";
const router = Router();
const registerSchema = z.object({ name: z.string().trim().min(2).max(80), email: z.string().email(), password: z.string().min(8).max(100) });
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });
function issueToken(id: string) { return jwt.sign({}, env.JWT_SECRET, { subject: id, expiresIn: "7d" }); }
router.post("/register", async (req, res, next) => {
  try {
    const data = registerSchema.parse(req.body);
    const email = data.email.toLowerCase();
    if (await User.exists({ email })) return res.status(409).json({ message: "Email is already registered" });
    const user = await User.create({ name: data.name, email, passwordHash: await bcrypt.hash(data.password, 12) });
    res.status(201).json({ token: issueToken(user.id), user: { id: user.id, name: user.name, email: user.email } });
  } catch (e: any) { if (e?.name === "ZodError") return res.status(400).json({ message: e.issues[0].message }); next(e); }
});
router.post("/login", async (req, res, next) => {
  try {
    const data = loginSchema.parse(req.body);
    const user = await User.findOne({ email: data.email.toLowerCase() });
    if (!user || !(await bcrypt.compare(data.password, user.passwordHash))) return res.status(401).json({ message: "Invalid email or password" });
    res.json({ token: issueToken(user.id), user: { id: user.id, name: user.name, email: user.email } });
  } catch (e: any) { if (e?.name === "ZodError") return res.status(400).json({ message: e.issues[0].message }); next(e); }
});
router.get("/me", authenticate, async (req, res, next) => {
  try {
    const user = await User.findById(req.userId).select("name email");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) { next(e); }
});
export default router;
