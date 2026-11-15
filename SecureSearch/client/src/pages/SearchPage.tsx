import { useState } from "react";
import { Search, FileSearch, Download, Sparkles, LockKeyhole, ShieldCheck } from "lucide-react";
import { api, getError } from "../api";
import type { SearchResult } from "../types";
import { formatSize } from "./Dashboard";
import { unlockExistingVault } from "../secure/diana/vault";
import { searchAndDecryptDocuments, type DecryptedSecureDocument } from "../secure/diana/documents";
import type { DianaClient } from "../secure/diana/diana";
import type { SecureVaultState } from "../secure/diana/workflow";

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [searched, setSearched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [terms, setTerms] = useState<string[]>([]);

  const [passphrase, setPassphrase] = useState("");
  const [secureReady, setSecureReady] = useState(false);
  const [secureClient, setSecureClient] = useState<DianaClient | null>(null);
  const [secureState, setSecureState] = useState<SecureVaultState | null>(null);
  const [secureQuery, setSecureQuery] = useState("");
  const [secureResults, setSecureResults] = useState<DecryptedSecureDocument[]>([]);
  const [secureSearched, setSecureSearched] = useState(false);
  const [secureBusy, setSecureBusy] = useState(false);
  const [secureError, setSecureError] = useState("");

  async function search(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setError("");
    try {
      const response = await api.post("/search", { query });
      setResults(response.data.results); setTerms(response.data.terms); setSearched(true);
    } catch (e) { setError(getError(e)); }
    finally { setBusy(false); }
  }

  async function download(d: SearchResult) {
    const response = await api.get(`/documents/${d.id}/download`, { responseType: "blob" });
    const url = URL.createObjectURL(response.data);
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = d.name;
    anchor.click(); URL.revokeObjectURL(url);
  }

  async function unlockSecureVault() {
    setSecureError("");
    try {
      const vault = await unlockExistingVault(passphrase);
      setSecureClient(vault.client); setSecureState(vault.state); setSecureReady(true);
    } catch (e) { setSecureError(getError(e)); }
  }

  async function searchSecure(e: React.FormEvent) {
    e.preventDefault();
    if (!secureClient || !secureState) return;
    setSecureBusy(true); setSecureError(""); setSecureSearched(false);
    try {
      const found = await searchAndDecryptDocuments({ query: secureQuery, client: secureClient, state: secureState });
      setSecureResults(found); setSecureSearched(true);
    } catch (e) { setSecureError(getError(e)); }
    finally { setSecureBusy(false); }
  }

  function downloadSecure(doc: DecryptedSecureDocument) {
    const url = URL.createObjectURL(doc.blob);
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = doc.name;
    anchor.click(); URL.revokeObjectURL(url);
  }

  return <>
    <div className="page-heading"><div><div className="eyebrow">SEARCH YOUR VAULT</div><h1>Find anything</h1><p>Search both the secure v2 vault and existing legacy documents.</p></div></div>

    <div className="panel upload-panel">
      <div className="section-head"><h2><LockKeyhole size={18}/> Secure v2 search</h2><span className="term-chip">Client-side query</span></div>
      <p className="muted">Keywords are processed in this browser. Diana addresses are checked against the locally trusted Merkle root before document decryption.</p>
      {!secureReady ? <div className="secure-unlock">
        <label className="field-label" htmlFor="secure-search-passphrase">Vault passphrase</label>
        <input id="secure-search-passphrase" className="form-input" type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} placeholder="Unlock your secure vault" autoComplete="current-password"/>
        <button className="primary-button" disabled={passphrase.length < 12} onClick={unlockSecureVault}>Unlock secure vault</button>
      </div> : <>
        <div className="success-box"><ShieldCheck size={17}/> Secure vault unlocked.</div>
        <form className="search-form" onSubmit={searchSecure}>
          <Search size={19}/>
          <input value={secureQuery} onChange={e => setSecureQuery(e.target.value)} placeholder="Search secure documents…" required/>
          <button className="primary-button" disabled={secureBusy}>{secureBusy ? "Verifying…" : "Secure search"}</button>
        </form>
      </>}
      {secureError && <pre className="error-box">{secureError}</pre>}
      {secureSearched && <>
        <div className="results-heading"><div><h2>{secureResults.length} verified result{secureResults.length === 1 ? "" : "s"}</h2><p>All query terms matched; index completeness and Merkle inclusion proofs passed.</p></div></div>
        {secureResults.length === 0 ? <div className="panel empty-state"><FileSearch size={28}/><strong>No matching secure documents</strong></div> :
          <div className="result-list">{secureResults.map(doc => <article className="panel result-card" key={doc.documentIndex}>
            <div className="result-top"><div className="file-icon">V2</div><div className="doc-info"><strong>{doc.name}</strong><span>Client-decrypted · index {doc.documentIndex}</span></div>
              <button className="secondary-button compact" onClick={() => downloadSecure(doc)}><Download size={15}/> Download</button>
            </div>
          </article>)}</div>}
      </>}
    </div>

    <div className="search-hero">
      <div className="search-mark"><FileSearch size={25}/></div><h2>Legacy HMAC search</h2>
      <p>Search legacy documents using multiple keywords. Every distinct term must match.</p>
      <form className="search-form" onSubmit={search}><Search size={19}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="e.g. encrypted index security" required/><button className="primary-button" disabled={busy}>{busy ? "Searching…" : "Search"}</button></form>
      <div className="search-hint"><Sparkles size={14}/> Legacy conjunctive keyword search · punctuation is ignored</div>
    </div>
    {error && <div className="error-box">{error}</div>}
    {searched && <>
      <div className="results-heading"><div><h2>{results.length} result{results.length === 1 ? "" : "s"}</h2><p>All terms matched: {terms.map(term => <span className="term-chip" key={term}>{term}</span>)}</p></div></div>
      {results.length === 0 ? <div className="panel empty-state"><FileSearch size={30}/><strong>No matching documents</strong><span>Try fewer or different keywords.</span></div> :
        <div className="result-list">{results.map(doc => <article className="panel result-card" key={doc.id}>
          <div className="result-top"><div className="file-icon">DOC</div><div className="doc-info"><strong>{doc.name}</strong><span>{formatSize(doc.size)} · {doc.wordCount.toLocaleString()} indexed words</span></div>
            <button className="secondary-button compact" onClick={() => download(doc)}><Download size={15}/> Download</button>
          </div><p className="snippet">{doc.snippet}</p>
        </article>)}</div>}
    </>}
  </>;
}
