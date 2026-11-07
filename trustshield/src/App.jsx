import { useState, useEffect } from "react";
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  useLocation,
} from "react-router-dom";
import { ToastProvider } from "@/hooks/useAuth";
import { Sidebar, TopBar, BottomNav } from "@/components/layout/layout";
import Landing from "@/pages/landing";
import UrlScan from "@/pages/url-scan";
import ScanReport from "@/pages/scan-report";
import Dashboard from "@/pages/dashboard";
import CommunityReports from "@/pages/community-reports";
import ReportWebsite from "@/pages/report-website";
import Watchlist from "@/pages/watchlist";
import Login from "@/pages/login";
import Register from "@/pages/register";
import ForgotPassword from "@/pages/forgot-password";
import Profile from "@/pages/profile";

const PUBLIC_ROUTES = ["/login", "/register", "/forgot-password"];

export default function App() {
  const [theme, setTheme] = useState("dark");
  const [mobileMenu, setMobileMenu] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("ts_theme");
    if (saved) setTheme(saved);
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    localStorage.setItem("ts_theme", next);
  };

  const location = useLocation();
  const isAuthenticated = localStorage.getItem("ts_token");

  const ProtectedRoutes = ({ children }) => (
    <>{isAuthenticated ? children : <Navigate to="/login" replace />}</>
  );

  const PublicRoutes = ({ children }) => (
    <>{!isAuthenticated && location.pathname !== "/"
      ? <Navigate to="/dashboard" replace />
      : children}</>
  );

  return (
    <ToastProvider>
      <div className="min-h-screen bg-navy-900 text-slate-200">
        {/* Desktop layout */}
        <div className="hidden md:flex flex-1">
          <Sidebar />
          <div className="flex-1 flex flex-col min-w-0">
            <TopBar
              onSearch={(v) => {
                if (v) {
                  const p = new URLSearchParams();
                  p.set("url", v);
                  window.location.href = `/scan?${p.toString()}`;
                }
              }}
              onNotify={() => {}}
              onProfile={() => {}}
              onThemeToggle={toggleTheme}
            />
            <main className="flex-1 overflow-y-auto p-6">
              <Routes location={location}>
                <Route path="/" element={<PublicRoutes><Navigate to="/dashboard" replace /></PublicRoutes>} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/forgot-password" element={<ForgotPassword />} />
                <Route element={<ProtectedRoutes />}>
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/scan" element={<UrlScan />} />
                  <Route path="/reports/:id" element={<ScanReport />} />
                  <Route path="/reports" element={<Navigate to="/scan" replace />} />
                  <Route path="/community" element={<CommunityReports />} />
                  <Route path="/report" element={<ReportWebsite />} />
                  <Route path="/watchlist" element={<Watchlist />} />
                  <Route path="/profile" element={<Profile />} />
                </Route>
              </Routes>
            </main>
          </div>
        </div>

        {/* Mobile layout */}
        <div className="md:hidden flex flex-col h-screen">
          <TopBar
            onSearch={(v) => {
              if (v) {
                const p = new URLSearchParams();
                p.set("url", v);
                window.location.href = `/scan?${p.toString()}`;
              }
            }}
            onNotify={() => {}}
            onProfile={() => {}}
            onThemeToggle={toggleTheme}
          />
          <button
            onClick={() => setMobileMenu(!mobileMenu)}
            className="px-4 py-3 text-slate-400 hover:text-white border-b border-white/5"
            aria-label="Toggle menu"
          >
            {mobileMenu ? "Hide menu" : "Menu"}{' '}
            <svg className="w-4 h-4 ml-1" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d={mobileMenu ? "M19 9l-7 7-7-7" : "M19 5l-7 7 7 7"} />
            </svg>
          </button>
          {mobileMenu && (
            <div className="p-4 border-b border-white/5 bg-navy-800/50 space-y-2">
              <button onClick={() => { setMobileMenu(false); window.location.href = "/dashboard"; }} className="text-slate-300 hover:text-white">Dashboard</button>
              <button onClick={() => { setMobileMenu(false); window.location.href = "/scan"; }} className="text-slate-300 hover:text-white">Scan URL</button>
              <button onClick={() => { setMobileMenu(false); window.location.href = "/community"; }} className="text-slate-300 hover:text-white">Community Reports</button>
              <button onClick={() => { setMobileMenu(false); window.location.href = "/watchlist"; }} className="text-slate-300 hover:text-white">Watchlist</button>
              <button onClick={() => { setMobileMenu(false); window.location.href = "/profile"; }} className="text-slate-300 hover:text-white">Profile</button>
            </div>
          )}
          <div className="flex-1 overflow-y-auto p-4">
            <Routes>
              <Route path="/" element={<Navigate to="/login" replace />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/forgot-password" element={<ForgotPassword />} />
              <Route element={isAuthenticated ? <></> : <Navigate to="/login" replace />}>
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/scan" element={<UrlScan />} />
                <Route path="/reports/:id" element={<ScanReport />} />
                <Route path="/community" element={<CommunityReports />} />
                <Route path="/report" element={<ReportWebsite />} />
                <Route path="/watchlist" element={<Watchlist />} />
                <Route path="/profile" element={<Profile />} />
              </Route>
            </Routes>
          </div>
          <BottomNav />
        </div>
      </div>
    </ToastProvider>
  );
}
