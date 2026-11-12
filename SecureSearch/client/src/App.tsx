import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import Layout from "./components/Layout";
import AuthPage from "./pages/AuthPage";
import Dashboard from "./pages/Dashboard";
import UploadPage from "./pages/UploadPage";
import DocumentsPage from "./pages/DocumentsPage";
import SearchPage from "./pages/SearchPage";
export default function App(){const {user}=useAuth();return <Routes><Route path="/login" element={user?<Navigate to="/"/>:<AuthPage mode="login"/>}/><Route path="/register" element={user?<Navigate to="/"/>:<AuthPage mode="register"/>}/><Route path="/" element={<ProtectedRoute><Layout/></ProtectedRoute>}><Route index element={<Dashboard/>}/><Route path="upload" element={<UploadPage/>}/><Route path="documents" element={<DocumentsPage/>}/><Route path="search" element={<SearchPage/>}/></Route><Route path="*" element={<Navigate to="/"/>}/></Routes>}
