import "fake-indexeddb/auto";
import { File } from "node:buffer";
import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import mongoose from "mongoose";
import { api } from "../../client/src/api";
import { createSecureVaultState, normalizeSecureKeywords } from "../../client/src/secure/diana/workflow";
import { uploadSecureDocument, searchAndDecryptDocuments } from "../../client/src/secure/diana/documents";
import { connectDatabase } from "../src/config/db";
import { Document } from "../src/models/Document";
import { SecureRecord } from "../src/models/SecureRecord";
import { User } from "../src/models/User";

type Doc = { id: string; title: string; source: string; url: string; bytes: number; text: string };
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const OUT = path.join(ROOT, "benchmark-results");
const BASE = (process.env.BENCHMARK_API_URL || "http://127.0.0.1:5000").replace(/\/$/, "");
const SEC_UA = process.env.SEC_USER_AGENT || "";
const MAX_BYTES = 50 * 1024;
const REPS = 5;
const STOP = new Set("about after again against all also among another any are because been before being between both but can could did does doing down during each few for from further had has have having here how into its itself just more most other our out over own same should some such than that the their them then there these they this those through too under until very was were what when where which while who will with would your document documents company report notice public information section".split(" "));
const storageShim = { token: "", getItem(k: string) { return k === "ss_token" ? this.token : null; }, setItem(k: string, v: string) { if (k === "ss_token") this.token = v; }, removeItem(k: string) { if (k === "ss_token") this.token = ""; } };
(globalThis as any).localStorage = storageShim;
api.defaults.baseURL = BASE + "/api";

function csv(rows: any[], cols: string[]) {
  return [cols.join(","), ...rows.map(r => cols.map(c => '"' + String(r[c] ?? "").replace(/"/g, '""') + '"').join(","))].join("\n") + "\n";
}
async function get(url: string, headers: Record<string, string> = {}) {
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(45000) });
  if (!response.ok) throw new Error("HTTP " + response.status + " while fetching " + url);
  const bytes = Buffer.from(await response.arrayBuffer());
  return { body: bytes.toString("utf8"), bytes: bytes.length };
}
function htmlText(html: string) {
  return html.replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<(script|style|noscript|svg)[^>]*>[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]+>/g, " ").replace(/&nbsp;|&#160;/gi, " ")
    .replace(/&amp;/gi, "&").replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<").replace(/&gt;/gi, ">")
    .replace(/&#(\d+);/g, (_m, n) => String.fromCodePoint(Number(n)))
    .replace(/\s+/g, " ").trim();
}
function cap(text: string) {
  const bytes = Buffer.from(text);
  return bytes.length <= MAX_BYTES ? text : bytes.subarray(0, MAX_BYTES).toString("utf8").replace(/\uFFFD+$/g, "");
}
async function fetchSec(): Promise<Doc[]> {
  if (!SEC_UA.includes("@")) throw new Error("Set SEC_USER_AGENT to a descriptive value containing a contact email.");
  const issuers = [["0000320193", "Apple"], ["0000789019", "Microsoft"], ["0001403161", "Visa"], ["0001018724", "Amazon"], ["0001045810", "NVIDIA"]];
  const docs: Doc[] = [];
  for (const pair of issuers) {
    const cik = pair[0], name = pair[1];
    const submissions = await get("https://data.sec.gov/submissions/CIK" + cik + ".json", { "User-Agent": SEC_UA });
    const recent = JSON.parse(submissions.body).filings?.recent;
    if (!recent) continue;
    const i = recent.form.findIndex((form: string) => form === "8-K");
    if (i < 0) continue;
    const accession = recent.accessionNumber[i].replace(/-/g, "");
    const url = "https://www.sec.gov/Archives/edgar/data/" + Number(cik) + "/" + accession + "/" + recent.primaryDocument[i];
    const page = await get(url, { "User-Agent": SEC_UA });
    const text = cap(htmlText(page.body));
    if (text.length < 100) continue;
    docs.push({ id: "SEC" + String(docs.length + 1).padStart(2, "0"), title: name + " 8-K " + recent.filingDate[i], source: "SEC EDGAR", url, bytes: page.bytes, text });
    if (docs.length === 5) break;
  }
  if (docs.length !== 5) throw new Error("SEC supplied only " + docs.length + " usable 8-K filings.");
  return docs;
}
async function fetchFederal(): Promise<Doc[]> {
  const url = new URL("https://www.federalregister.gov/api/v1/documents.json");
  url.searchParams.set("per_page", "40");
  url.searchParams.set("order", "newest");
  url.searchParams.append("conditions[type][]", "NOTICE");
  for (const field of ["title", "html_url", "document_number"]) url.searchParams.append("fields[]", field);
  const listing = await get(url.toString(), { "Accept": "application/json" });
  const docs: Doc[] = [];
  for (const item of (JSON.parse(listing.body).results || [])) {
    if (!item.html_url) continue;
    try {
      const page = await get(item.html_url);
      const text = cap(htmlText(page.body));
      if (text.length < 100) continue;
      docs.push({ id: "FR" + String(docs.length + 1).padStart(2, "0"), title: item.title || item.document_number, source: "Federal Register", url: item.html_url, bytes: page.bytes, text });
      if (docs.length === 5) break;
    } catch (error) { console.warn("Skipping Federal Register source:", String(error)); }
  }
  if (docs.length !== 5) throw new Error("Federal Register supplied only " + docs.length + " usable notices.");
  return docs;
}
function chooseQueries(docs: Doc[]) {
  const frequency = new Map<string, number>();
  const words = docs.map(d => [...new Set(normalizeSecureKeywords(d.text).filter(w => w.length >= 5 && !STOP.has(w)))]);
  for (const list of words) for (const word of list) frequency.set(word, (frequency.get(word) || 0) + 1);
  return new Map(docs.map((d, i) => [d.id, words[i].sort((a, b) => (frequency.get(a)! - frequency.get(b)!) || (b.length - a.length))[0] || ""]));
}
async function mongoStats() {
  const db = mongoose.connection.db!;
  const stats = await db.command({ dbStats: 1 });
  async function collection(name: string) {
    try { return await db.command({ collStats: name }); }
    catch { return { count: 0, size: 0, storageSize: 0, totalIndexSize: 0 }; }
  }
  const legacy = await collection("documents"), secure = await collection("securerecords");
  return {
    db_data_bytes: stats.dataSize || 0, db_storage_bytes: stats.storageSize || 0, db_index_bytes: stats.indexSize || 0,
    legacy_count: legacy.count || 0, legacy_data_bytes: legacy.size || 0, legacy_storage_bytes: legacy.storageSize || 0, legacy_index_bytes: legacy.totalIndexSize || 0,
    secure_count: secure.count || 0, secure_data_bytes: secure.size || 0, secure_storage_bytes: secure.storageSize || 0, secure_index_bytes: secure.totalIndexSize || 0
  };
}
async function postJson(url: string, token: string, body: any) {
  const response = await fetch(url, { method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await response.json();
  if (!response.ok) throw new Error("Search request failed: " + JSON.stringify(data));
  return data;
}
async function main() {
  const health = await fetch(BASE + "/api/health");
  if (!health.ok) throw new Error("Start SecureSearch API before running this benchmark.");
  const docs = [...await fetchSec(), ...await fetchFederal()];
  const queries = chooseQueries(docs);
  if ([...queries.values()].some(q => !q)) throw new Error("A document did not contain a suitable searchable keyword.");

  const run = new Date().toISOString().replace(/[:.]/g, "-");
  const dir = path.join(OUT, run), docDir = path.join(dir, "documents");
  await mkdir(docDir, { recursive: true });
  const manifest: any[] = [];
  for (const d of docs) {
    const filename = d.id + ".txt";
    await writeFile(path.join(docDir, filename), d.text);
    manifest.push({ doc_id: d.id, title: d.title, source: d.source, source_url: d.url, source_bytes: d.bytes, text_bytes: Buffer.byteLength(d.text), query: queries.get(d.id), local_file: "documents/" + filename });
  }

  await connectDatabase();
  const email = "securesearch-benchmark-" + randomUUID() + "@example.invalid";
  const password = "Bench-" + randomUUID() + "-Aa9!";
  const registration = await fetch(BASE + "/api/auth/register", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "SecureSearch Benchmark", email, password })
  });
  const account = await registration.json();
  if (!registration.ok) throw new Error("Temporary benchmark account creation failed: " + JSON.stringify(account));
  const token = account.token, owner = account.user.id;
  storageShim.setItem("ss_token", token);

  const uploads: any[] = [], searches: any[] = [], storage: any[] = [];
  let cleanupError = "";
  try {
    storage.push({ phase: "before_upload", ...await mongoStats() });
    for (const d of docs) {
      const form = new FormData();
      form.append("file", new Blob([d.text], { type: "text/plain" }), d.id + ".txt");
      const start = performance.now();
      const response = await fetch(BASE + "/api/documents", { method: "POST", headers: { Authorization: "Bearer " + token }, body: form });
      const result = await response.json();
      if (!response.ok) throw new Error("Legacy upload failed for " + d.id + ": " + JSON.stringify(result));
      uploads.push({ system: "legacy", doc_id: d.id, text_bytes: Buffer.byteLength(d.text), upload_ms: performance.now() - start, status: "ok" });
    }
    storage.push({ phase: "after_legacy", ...await mongoStats() });

    const vault = await createSecureVaultState();
    let state = vault.state;
    const passphrase = "Temporary-Benchmark-" + randomUUID() + "-Only";
    for (const d of docs) {
      const file = new File([d.text], d.id + ".txt", { type: "text/plain" });
      const start = performance.now();
      state = await uploadSecureDocument({ file, client: vault.client, state, passphrase });
      uploads.push({ system: "secure_v2", doc_id: d.id, text_bytes: Buffer.byteLength(d.text), upload_ms: performance.now() - start, unique_keywords: normalizeSecureKeywords(d.text).length, status: "ok" });
    }
    storage.push({ phase: "after_secure_v2", ...await mongoStats() });

    for (const d of docs) {
      const query = queries.get(d.id)!;
      await postJson(BASE + "/api/search", token, { query });
      await searchAndDecryptDocuments({ query, client: vault.client, state });
      for (let repetition = 1; repetition <= REPS; repetition++) {
        let start = performance.now();
        const legacy = await postJson(BASE + "/api/search", token, { query });
        searches.push({ system: "legacy", doc_id: d.id, query, repetition, search_ms: performance.now() - start, result_count: legacy.count, expected_found: (legacy.results || []).some((x: any) => x.name === d.id + ".txt") });

        start = performance.now();
        vault.client.searchAddresses(query);
        const trapdoorMs = performance.now() - start;
        start = performance.now();
        const secure = await searchAndDecryptDocuments({ query, client: vault.client, state });
        searches.push({ system: "secure_v2", doc_id: d.id, query, repetition, trapdoor_ms: trapdoorMs, search_ms: performance.now() - start, result_count: secure.length, expected_found: secure.some(x => x.name === d.id + ".txt") });
      }
    }
    storage.push({ phase: "before_cleanup", ...await mongoStats() });
  } finally {
    try {
      await Document.deleteMany({ owner });
      await SecureRecord.deleteMany({ owner });
      await User.deleteOne({ _id: owner });
      storage.push({ phase: "after_cleanup", ...await mongoStats() });
    } catch (error) { cleanupError = String(error); }
    await mongoose.disconnect();
  }

  const writeCsv = (name: string, rows: any[], columns: string[]) => writeFile(path.join(dir, name), csv(rows, columns));
  await writeCsv("dataset_manifest.csv", manifest, ["doc_id", "title", "source", "source_url", "source_bytes", "text_bytes", "query", "local_file"]);
  await writeCsv("upload.csv", uploads, ["system", "doc_id", "text_bytes", "upload_ms", "unique_keywords", "status"]);
  await writeCsv("search.csv", searches, ["system", "doc_id", "query", "repetition", "trapdoor_ms", "search_ms", "result_count", "expected_found"]);
  await writeCsv("storage.csv", storage, ["phase", "db_data_bytes", "db_storage_bytes", "db_index_bytes", "legacy_count", "legacy_data_bytes", "legacy_storage_bytes", "legacy_index_bytes", "secure_count", "secure_data_bytes", "secure_storage_bytes", "secure_index_bytes"]);

  const summary: any[] = [];
  for (const system of ["legacy", "secure_v2"]) {
    const up = uploads.filter(x => x.system === system).map(x => x.upload_ms);
    const sr = searches.filter(x => x.system === system);
    const times = sr.map(x => x.search_ms).sort((a, b) => a - b);
    const avg = (values: number[]) => values.reduce((a, b) => a + b, 0) / (values.length || 1);
    summary.push({ system, documents: up.length, mean_upload_ms: avg(up), mean_search_ms: avg(times), median_search_ms: times[Math.floor(times.length / 2)] || 0, search_trials: times.length, correctness_passes: sr.filter(x => x.expected_found).length });
  }
  await writeCsv("summary.csv", summary, ["system", "documents", "mean_upload_ms", "mean_search_ms", "median_search_ms", "search_trials", "correctness_passes"]);
  await writeFile(path.join(dir, "run-info.txt"), "Run: " + run + "\nAPI: " + BASE + "\n10 public documents: 5 SEC EDGAR + 5 Federal Register.\nText cap: 50 KiB per document.\nSearch repetitions: " + REPS + " after warm-up.\nTimings are end-to-end and include network/API overhead.\nCleanup: " + (cleanupError || "attempted for the isolated temporary user") + "\n");
  console.log("Benchmark complete. Results: " + dir);
  if (cleanupError) console.error("WARNING: cleanup failed: " + cleanupError);
}
main().catch(async error => {
  console.error("Benchmark failed:", error);
  try { await mongoose.disconnect(); } catch {}
  process.exitCode = 1;
});
