export function normalizeText(input: string): string {
  return input.normalize("NFKC").toLocaleLowerCase().replace(/\u0000/g, " ");
}
export function tokenize(input: string): string[] {
  const matches = normalizeText(input).match(/[\p{L}\p{N}_]+/gu) || [];
  return [...new Set(matches.filter(w => w.length > 1 && w.length <= 64))];
}
export function makeSnippet(text: string, terms: string[]): string {
  const clean = text.replace(/\s+/g, " ").trim();
  const lower = clean.toLocaleLowerCase();
  const positions = terms.map(t => lower.indexOf(t)).filter(i => i >= 0);
  const start = Math.max(0, (positions.length ? Math.min(...positions) : 0) - 90);
  return `${start ? "…" : ""}${clean.slice(start, start + 240)}${start + 240 < clean.length ? "…" : ""}`;
}
