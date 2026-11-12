import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { env } from "./config/env.js";
import { connectDatabase } from "./config/db.js";
import authRoutes from "./routes/auth.routes.js";
import documentRoutes from "./routes/document.routes.js";
import searchRoutes from "./routes/search.routes.js";
import { notFound, errorHandler } from "./middleware/error.js";

const app = express();
app.use(helmet());
app.use(cors({ origin: env.CLIENT_ORIGIN, credentials: false }));
app.use(express.json({ limit: "1mb" }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));
app.get("/api/health", (_req, res) => res.json({ status: "ok", service: "SecureSearch API" }));
app.use("/api/auth", authRoutes);
app.use("/api/documents", documentRoutes);
app.use("/api/search", searchRoutes);
app.use(notFound);
app.use(errorHandler);

connectDatabase().then(() => app.listen(env.PORT, () => console.log(`API listening on http://localhost:${env.PORT}`)))
  .catch(err => { console.error("Could not connect to MongoDB", err); process.exit(1); });
