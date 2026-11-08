import React, { useState, useEffect } from "react";
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
import { AISecurityAssistant } from "@/components/ui/ai-security-assistant";
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
import OAuthCallback from "@/pages/oauth-callback";

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error("UI Error Caught by Boundary:", error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#070b14] flex flex-col items-center justify-center p-6 text-center">
          <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 mb-4 text-xl font-bold">
            !
          </div>
          <h2 className="text-xl font-bold text-white mb-2">Interface Render Notice</h2>
          <p className="text-sm text-slate-400 max-w-md mb-6 font-mono bg-black/40 p-3 rounded-lg border border-white/5 text-xs text-red-300">
            {this.state.error?.message || "Unexpected rendering exception"}
          </p>
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null });
              window.location.reload();
            }}
            className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs uppercase tracking-wider transition-colors cursor-pointer"
          >
            Reload Interface
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function ProtectedRoute() {
  const { isAuthenticated, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#070b14] text-cyan-400 font-mono text-sm">
        <div className="flex items-center gap-3">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span>Authenticating SecOps session...</span>
        </div>
      </div>
    );
  }

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

        <AISecurityAssistant />

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
          <Route path="/auth/callback" element={<OAuthCallback />} />

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
