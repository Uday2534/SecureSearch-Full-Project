import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { env } from "../config/env.js";
declare global { namespace Express { interface Request { userId?: string } } }
export function authenticate(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return res.status(401).json({ message: "Authentication required" });
  try {
    const payload = jwt.verify(header.slice(7), env.JWT_SECRET) as { sub: string };
    req.userId = payload.sub;
    next();
  } catch { return res.status(401).json({ message: "Invalid or expired token" }); }
}
