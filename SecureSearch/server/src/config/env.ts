import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const envPath = process.env.ENV_FILE
  ? path.resolve(process.env.ENV_FILE)
  : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../.env");
dotenv.config({ path: envPath });

const schema = z.object({
  MONGODB_URI: z.string().default("mongodb://127.0.0.1:27017/securesearch"),
  PORT: z.coerce.number().default(5000),
  CLIENT_ORIGIN: z.string().default("http://localhost:5173"),
  JWT_SECRET: z.string().min(32),
  MASTER_KEY: z.string().regex(/^[a-fA-F0-9]{64}$/, "MASTER_KEY must be 64 hex characters"),
  MAX_FILE_SIZE_MB: z.coerce.number().positive().default(25)
});
export const env = schema.parse(process.env);
