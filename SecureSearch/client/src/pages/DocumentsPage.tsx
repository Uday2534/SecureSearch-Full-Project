import { useEffect,useState } from "react";
import { Download, Trash2, Files, RefreshCw } from "lucide-react";
import { api,getError } from "../api";
import type { Doc } from "../types";
import { formatSize } from "./Dashboard";
export default function DocumentsPage(){const [docs,setDocs]=useState<Doc[]>([]);const [error,setError]=useState("");const [loading,setLoading]=useState(true);
 async function load(){setLoading(true);try{const r=await api.get("/documents");setDocs(r.data.documents);setError("");}catch(e){setError(getError(e));}finally{setLoading(false);}}
 useEffect(()=>{load();},[]);
 async function download(d:Doc){try{const r=await api.get(`/documents/${d.id}/download`,{responseType:"blob"});const url=URL.createObjectURL(r.data);const a=document.createElement("a");a.href=url;a.download=d.name;a.click();URL.revokeObjectURL(url);}catch(e){setError(getError(e));}}
 async function remove(d:Doc){if(!confirm(`Delete "${d.name}"?`))return;try{await api.delete(`/documents/${d.id}`);setDocs(old=>old.filter(x=>x.id!==d.id));}catch(e){setError(getError(e));}}
 return <><div className="page-heading"><div><div className="eyebrow">YOUR PRIVATE FILES</div><h1>My documents</h1><p>Manage encrypted documents in your workspace.</p></div><button className="secondary-button" onClick={load}><RefreshCw size={16}/> Refresh</button></div>{error&&<div className="error-box">{error}</div>}<div className="panel">{loading?<div className="empty-state">Loading…</div>:docs.length===0?<div className="empty-state"><Files size={30}/><strong>Your vault is empty</strong><span>Upload a document to see it here.</span></div>:<div className="doc-list">{docs.map(d=><div className="doc-row" key={d.id}><div className="file-icon">{(d.extension||"").replace(".","").slice(0,4).toUpperCase()}</div><div className="doc-info"><strong>{d.name}</strong><span>{formatSize(d.size)} · {d.wordCount.toLocaleString()} indexed words · {new Date(d.createdAt).toLocaleString()}</span></div><div className="doc-actions"><button className="icon-button" title="Download decrypted original" onClick={()=>download(d)}><Download size={17}/></button><button className="icon-button danger" title="Delete" onClick={()=>remove(d)}><Trash2 size={17}/></button></div></div>)}</div>}</div></>;
}
