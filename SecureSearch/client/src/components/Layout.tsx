import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { FileSearch, Files, LayoutDashboard, LogOut, ShieldCheck, UploadCloud } from "lucide-react";
import { useAuth } from "../context/AuthContext";
export default function Layout(){
 const {user,logout}=useAuth(); const navigate=useNavigate();
 const links=[["/", "Overview",LayoutDashboard],["/upload","Upload files",UploadCloud],["/documents","My documents",Files],["/search","Search",FileSearch]] as const;
 return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-icon"><ShieldCheck size={21}/></div><span>Secure<span className="mint">Search</span></span></div><div className="side-label">WORKSPACE</div><nav>{links.map(([to,label,Icon])=><NavLink key={to} to={to} end={to==="/"} className={({isActive})=>`nav-link ${isActive?"active":""}`}><Icon size={18}/>{label}</NavLink>)}</nav><div className="sidebar-bottom"><div className="avatar">{user?.name?.[0]?.toUpperCase()}</div><div className="user-meta"><strong>{user?.name}</strong><span>{user?.email}</span></div><button className="icon-button" title="Sign out" onClick={()=>{logout();navigate("/login");}}><LogOut size={17}/></button></div></aside><main className="main-area"><header className="topbar"><span>Private workspace</span><span className="secure-label"><span className="status-dot"/> Local encryption enabled</span></header><div className="page"><Outlet/></div></main></div>;
}
