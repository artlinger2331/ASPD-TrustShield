import { useState, useEffect } from "react";
import {
  Routes,
  Route,
  Navigate,
  Outlet,
  useNavigate,
  useLocation,
} from "react-router-dom";
import { AuthProvider, ToastProvider, useAuth } from "@/hooks/useAuth";
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

function ProtectedRoute() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <Outlet />;
}

function AppLayout({ toggleTheme }) {
  const [mobileMenu, setMobileMenu] = useState(false);
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-navy-900 text-slate-200 flex flex-col">
      {/* Desktop sidebar */}
      <Sidebar className="hidden md:flex" />

      {/* Main app area */}
      <div className="flex-1 flex flex-col min-w-0 md:pl-64">
        <TopBar
          onSearch={(v) => {
            if (v) {
              navigate(`/scan?url=${encodeURIComponent(v)}`);
            }
          }}
          onNotify={() => {}}
          onProfile={() => navigate("/profile")}
          onThemeToggle={toggleTheme}
          onMenuToggle={() => setMobileMenu(!mobileMenu)}
        />

        {/* Mobile menu dropdown */}
        {mobileMenu && (
          <div className="md:hidden p-4 border-b border-white/5 bg-navy-800/90 backdrop-blur space-y-2 sticky top-[57px] z-20">
            <button
              onClick={() => { setMobileMenu(false); navigate("/dashboard"); }}
              className="block w-full text-left py-2 px-3 rounded-lg text-slate-300 hover:text-white hover:bg-white/5"
            >
              Dashboard
            </button>
            <button
              onClick={() => { setMobileMenu(false); navigate("/scan"); }}
              className="block w-full text-left py-2 px-3 rounded-lg text-slate-300 hover:text-white hover:bg-white/5"
            >
              Scan URL
            </button>
            <button
              onClick={() => { setMobileMenu(false); navigate("/community"); }}
              className="block w-full text-left py-2 px-3 rounded-lg text-slate-300 hover:text-white hover:bg-white/5"
            >
              Community Reports
            </button>
            <button
              onClick={() => { setMobileMenu(false); navigate("/watchlist"); }}
              className="block w-full text-left py-2 px-3 rounded-lg text-slate-300 hover:text-white hover:bg-white/5"
            >
              Watchlist
            </button>
            <button
              onClick={() => { setMobileMenu(false); navigate("/profile"); }}
              className="block w-full text-left py-2 px-3 rounded-lg text-slate-300 hover:text-white hover:bg-white/5"
            >
              Profile
            </button>
          </div>
        )}

        <main className="flex-1 p-4 md:p-6 pb-20 md:pb-6 overflow-y-auto">
          <Outlet />
        </main>

        <div className="md:hidden">
          <BottomNav />
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [theme, setTheme] = useState(() => {
    if (typeof window !== "undefined") {
      return localStorage.getItem("ts_theme") || "dark";
    }
    return "dark";
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("ts_theme", theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  };

  return (
    <AuthProvider>
      <ToastProvider>
        <Routes>
          {/* Public standalone pages */}
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />

          {/* Authenticated / App layout pages */}
          <Route element={<AppLayout toggleTheme={toggleTheme} />}>
            <Route element={<ProtectedRoute />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/scan" element={<UrlScan />} />
              <Route path="/reports/:id" element={<ScanReport />} />
              <Route path="/report/:id" element={<ScanReport />} />
              <Route path="/reports" element={<ScanReport />} />
              <Route path="/community" element={<CommunityReports />} />
              <Route path="/report" element={<ReportWebsite />} />
              <Route path="/report-website" element={<ReportWebsite />} />
              <Route path="/watchlist" element={<Watchlist />} />
              <Route path="/profile" element={<Profile />} />
              <Route path="/settings" element={<Profile />} />
            </Route>
          </Route>

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ToastProvider>
    </AuthProvider>
  );
}
