import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api } from "../api";
import type { User } from "../types";
type AuthValue = { user: User | null; loading: boolean; login: (email:string,password:string)=>Promise<void>; register:(name:string,email:string,password:string)=>Promise<void>; logout:()=>void; };
const AuthContext = createContext<AuthValue | null>(null);
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user,setUser] = useState<User|null>(null); const [loading,setLoading] = useState(true);
  useEffect(() => { if (!localStorage.getItem("ss_token")) { setLoading(false); return; }
    api.get("/auth/me").then(r=>setUser(r.data.user)).catch(()=>localStorage.removeItem("ss_token")).finally(()=>setLoading(false));
  }, []);
  async function login(email:string,password:string) { const r=await api.post("/auth/login",{email,password}); localStorage.setItem("ss_token",r.data.token); setUser(r.data.user); }
  async function register(name:string,email:string,password:string) { const r=await api.post("/auth/register",{name,email,password}); localStorage.setItem("ss_token",r.data.token); setUser(r.data.user); }
  function logout(){ localStorage.removeItem("ss_token"); setUser(null); }
  return <AuthContext.Provider value={{user,loading,login,register,logout}}>{children}</AuthContext.Provider>;
}
export function useAuth(){ const value=useContext(AuthContext); if(!value) throw new Error("useAuth must be inside AuthProvider"); return value; }
