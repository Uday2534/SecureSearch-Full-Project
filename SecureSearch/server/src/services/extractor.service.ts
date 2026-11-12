import path from "node:path";
import { parseOfficeAsync } from "officeparser";
import pdfParse from "pdf-parse";
import mammoth from "mammoth";
import XLSX from "xlsx";
import { parse as parseCsv } from "csv-parse/sync";

const MAX_TEXT_CHARS = 8_000_000;
function decode(buffer: Buffer) { return buffer.toString("utf8").replace(/^\uFEFF/, ""); }
function stripHtml(s: string) {
  return s.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ").replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)));
}
export async function extractText(buffer: Buffer, filename: string): Promise<string> {
  const ext = path.extname(filename).toLowerCase();
  let text = "";
  if (ext === ".pdf") {
    const result = await pdfParse(buffer);
    text = result.text;
  } else if (ext === ".docx") {
    const result = await mammoth.extractRawText({ buffer });
    text = result.value;
  } else if ([".xlsx", ".xls"].includes(ext)) {
    const wb = XLSX.read(buffer, { type: "buffer" });
    text = wb.SheetNames.map(name => `Sheet: ${name}\n${XLSX.utils.sheet_to_csv(wb.Sheets[name])}`).join("\n");
  } else if (ext === ".csv") {
    const rows = parseCsv(buffer, { relax_quotes: true, skip_empty_lines: true });
    text = rows.map((row: unknown[]) => row.join(" ")).join("\n");
  } else if ([".txt", ".md", ".markdown", ".log"].includes(ext)) {
    text = decode(buffer);
  } else if ([".html", ".htm", ".xml", ".rtf"].includes(ext)) {
    text = stripHtml(decode(buffer).replace(/\\'[0-9a-f]{2}/gi, " ").replace(/\\[a-z]+\d* ?/gi, " "));
  } else if (ext === ".json") {
    const parsed = JSON.parse(decode(buffer));
    text = JSON.stringify(parsed, null, 2);
  } else if ([".doc", ".ppt", ".pptx", ".odt", ".ods", ".odp"].includes(ext)) {
    text = await parseOfficeAsync(buffer);
  } else {
    throw new Error(`Unsupported file type: ${ext || "unknown"}`);
  }
  text = text.replace(/\u0000/g, " ").trim();
  if (!text) throw new Error("No text could be extracted. If this is a scanned PDF, OCR is required.");
  if (text.length > MAX_TEXT_CHARS) text = text.slice(0, MAX_TEXT_CHARS);
  return text;
}
