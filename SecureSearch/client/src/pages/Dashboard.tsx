import { useEffect,useState } from "react";
import { Files, Search, UploadCloud, ShieldCheck, ArrowUpRight } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { Doc } from "../types";
export default function Dashboard(){const [docs,setDocs]=useState<Doc[]>([]);const [loading,setLoading]=useState(true);
 useEffect(()=>{api.get("/documents").then(r=>setDocs(r.data.documents)).finally(()=>setLoading(false));},[]);
 const totalSize=docs.reduce((s,d)=>s+d.size,0);
 return <><div className="page-heading"><div><div className="eyebrow">YOUR WORKSPACE</div><h1>Overview</h1><p>Search across your documents without exposing readable files at rest.</p></div><Link className="primary-button" to="/upload"><UploadCloud size={17}/> Upload documents</Link></div>
 <div className="stats-grid"><div className="stat-card"><div className="stat-icon"><Files/></div><span>Stored documents</span><strong>{loading?"—":docs.length}</strong><small>In your private workspace</small></div><div className="stat-card"><div className="stat-icon"><Search/></div><span>Indexed vocabulary</span><strong>{loading?"—":docs.reduce((s,d)=>s+d.wordCount,0).toLocaleString()}</strong><small>Unique words per file summed</small></div><div className="stat-card"><div className="stat-icon"><ShieldCheck/></div><span>Encrypted storage</span><strong>AES-256</strong><small>Authenticated encryption</small></div></div>
 <div className="section-head"><div><h2>Recent documents</h2><p>Your latest uploads</p></div><Link to="/documents" className="text-link">View all <ArrowUpRight size={15}/></Link></div>
 <div className="panel">{loading?<div className="empty-state">Loading documents…</div>:docs.length===0?<div className="empty-state"><Files size={30}/><strong>No documents yet</strong><span>Upload your first file to start searching.</span><Link to="/upload" className="text-link">Upload a document</Link></div>:<div className="doc-list">{docs.slice(0,5).map(d=><div className="doc-row" key={d.id}><div className="file-icon">{(d.extension||"").replace(".","").slice(0,4).toUpperCase()}</div><div className="doc-info"><strong>{d.name}</strong><span>{d.wordCount.toLocaleString()} indexed words · {formatSize(d.size)}</span></div><span className="doc-date">{new Date(d.createdAt).toLocaleDateString()}</span></div>)}</div>}</div>
 <div className="notice"><ShieldCheck size={18}/><div><strong>Privacy note</strong><p>Original files and extracted text are encrypted at rest. Search uses deterministic keyed tokens, which still reveal some search-pattern information.</p></div></div></>;
}
export function formatSize(n:number){if(n<1024)return `${n} B`;if(n<1048576)return `${(n/1024).toFixed(1)} KB`;return `${(n/1048576).toFixed(1)} MB`;}
