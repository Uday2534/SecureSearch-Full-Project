import { useRef, useState } from "react";
import { UploadCloud, FileText, CheckCircle2, X, ShieldCheck, LockKeyhole } from "lucide-react";
import { api, getError } from "../api";
import { unlockOrCreateVault } from "../secure/diana/vault";
import { uploadSecureDocument } from "../secure/diana/documents";
import type { DianaClient } from "../secure/diana/diana";
import type { SecureVaultState } from "../secure/diana/workflow";

const legacyTypes = ".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.csv,.txt,.md,.markdown,.html,.htm,.xml,.json,.rtf,.odt,.ods,.odp,.log";
const secureTypes = ".txt,.csv,.md,.markdown,.json,.html,.htm,.xml,.log";

export default function UploadPage() {
  const ref = useRef<HTMLInputElement>(null);
  const secureRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const [passphrase, setPassphrase] = useState("");
  const [secureReady, setSecureReady] = useState(false);
  const [secureClient, setSecureClient] = useState<DianaClient | null>(null);
  const [secureState, setSecureState] = useState<SecureVaultState | null>(null);
  const [secureFile, setSecureFile] = useState<File | null>(null);
  const [secureStatus, setSecureStatus] = useState("");
  const [secureError, setSecureError] = useState("");
  const [secureBusy, setSecureBusy] = useState(false);

  function add(list: FileList | null) {
    if (!list) return;
    setFiles(old => [...old, ...Array.from(list)].filter((file, i, all) =>
      all.findIndex(item => item.name === file.name && item.size === file.size) === i));
    setMessage("");
  }

  async function uploadLegacy() {
    if (!files.length) return;
    setBusy(true); setError(""); setMessage("");
    let ok = 0; const failures: string[] = [];
    for (const file of files) {
      const body = new FormData(); body.append("file", file);
      try {
        await api.post("/documents", body, { headers: { "Content-Type": "multipart/form-data" } });
        ok++;
      } catch (e) { failures.push(`${file.name}: ${getError(e)}`); }
    }
    setBusy(false); setFiles([]);
    if (failures.length) setError(failures.join("\n"));
    if (ok) setMessage(`${ok} legacy document${ok === 1 ? "" : "s"} uploaded. Legacy search uses the existing HMAC workflow.`);
  }

  async function unlockSecureVault() {
    setSecureError(""); setSecureStatus("");
    try {
      const vault = await unlockOrCreateVault(passphrase);
      setSecureClient(vault.client);
      setSecureState(vault.state);
      setSecureReady(true);
      setSecureStatus("Secure vault unlocked. New secure uploads are encrypted in this browser.");
    } catch (e) { setSecureError(getError(e)); }
  }

  async function uploadSecure() {
    if (!secureFile || !secureClient || !secureState) return;
    setSecureBusy(true); setSecureError(""); setSecureStatus("");
    try {
      const next = await uploadSecureDocument({
        file: secureFile,
        client: secureClient,
        state: secureState,
        passphrase,
      });
      setSecureState(next);
      setSecureFile(null);
      if (secureRef.current) secureRef.current.value = "";
      setSecureStatus("Secure upload complete. The file and keyword postings were encrypted/generated in the browser, and the client verified its updated index commitment.");
    } catch (e) { setSecureError(getError(e)); }
    finally { setSecureBusy(false); }
  }

  return <>
    <div className="page-heading"><div><div className="eyebrow">ADD TO YOUR VAULT</div><h1>Upload documents</h1><p>Choose the legacy workflow or the new client-side secure workflow.</p></div></div>

    <div className="panel upload-panel">
      <div className="section-head"><h2><LockKeyhole size={18}/> Secure v2 upload</h2><span className="term-chip">Forward-private index</span></div>
      <p className="muted">The browser extracts searchable text, encrypts the document, and generates Diana postings. The server receives opaque records only.</p>
      {!secureReady ? <div className="secure-unlock">
        <label className="field-label" htmlFor="secure-vault-passphrase">Vault passphrase</label>
        <input id="secure-vault-passphrase" className="form-input" type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} placeholder="At least 12 characters" autoComplete="new-password"/>
        <button className="primary-button" disabled={passphrase.length < 12} onClick={unlockSecureVault}>Create / unlock secure vault</button>
      </div> : <div className="secure-upload-controls">
        <div className="success-box"><ShieldCheck size={17}/> Secure vault unlocked in this browser.</div>
        <div className="dropzone" onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); setSecureFile(e.dataTransfer.files[0] ?? null); }} onClick={() => secureRef.current?.click()}>
          <div className="upload-icon"><UploadCloud size={27}/></div>
          <strong>{secureFile ? secureFile.name : <>Drop a file here or <span className="mint">browse</span></>}</strong>
          <span>Secure v2 currently supports TXT, CSV, Markdown, JSON, HTML, XML and LOG</span>
          <small>8 MB maximum per file · file names and contents are encrypted</small>
          <input ref={secureRef} hidden type="file" accept={secureTypes} onChange={e => setSecureFile(e.target.files?.[0] ?? null)}/>
        </div>
        <button className="primary-button full" disabled={!secureFile || secureBusy} onClick={uploadSecure}>{secureBusy ? "Encrypting and indexing…" : "Upload securely"}</button>
      </div>}
      {secureStatus && <div className="success-box"><CheckCircle2 size={17}/>{secureStatus}</div>}
      {secureError && <pre className="error-box">{secureError}</pre>}
    </div>

    <div className="panel upload-panel">
      <div className="section-head"><h2>Legacy upload</h2><span className="term-chip">Existing HMAC workflow</span></div>
      <p className="muted">This preserves the original server-side extraction and deterministic HMAC indexing workflow. It is not forward-private.</p>
      <div className="dropzone" onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); add(e.dataTransfer.files); }} onClick={() => ref.current?.click()}>
        <div className="upload-icon"><UploadCloud size={27}/></div>
        <strong>Drop files here or <span className="mint">browse</span></strong>
        <span>Choose one or more documents to upload</span>
        <small>PDF, Word, Excel, PowerPoint, CSV, TXT, Markdown, HTML, XML, JSON, RTF and OpenDocument · 25 MB per file</small>
        <input ref={ref} hidden type="file" multiple accept={legacyTypes} onChange={e => add(e.target.files)}/>
      </div>
      {files.length > 0 && <div className="selected-files">
        <div className="section-head"><h2>Selected files ({files.length})</h2><button className="text-link" onClick={() => setFiles([])}>Clear all</button></div>
        {files.map((file, i) => <div className="selected-file" key={`${file.name}-${i}`}><FileText size={18}/><span>{file.name}</span><small>{(file.size / 1024 / 1024).toFixed(2)} MB</small><button className="icon-button" onClick={() => setFiles(old => old.filter((_, j) => j !== i))}><X size={16}/></button></div>)}
        <button className="primary-button full" disabled={busy} onClick={uploadLegacy}>{busy ? "Uploading…" : `Upload ${files.length} file${files.length === 1 ? "" : "s"} (legacy)`}</button>
      </div>}
      {message && <div className="success-box"><CheckCircle2 size={17}/>{message}</div>}
      {error && <pre className="error-box">{error}</pre>}
    </div>
    <div className="notice"><ShieldCheck size={18}/><div><strong>Important distinction</strong><p>Only documents uploaded through Secure v2 use the client-side Diana workflow. Legacy documents remain in the original HMAC system and are not silently migrated.</p></div></div>
  </>;
}
