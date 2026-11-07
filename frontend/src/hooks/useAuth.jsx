import { createContext, useContext, useState, useCallback, useEffect } from "react";
import { authApi } from "@/utils/api";

const ToastContext = createContext(null);

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const toast = useCallback(
    ({ title, description, type = "info", duration = 4000 } = {}) => {
      const id = Math.random().toString(36).slice(2);
      setToasts((prev) => [...prev, { id, title, description, type }]);
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, duration);
      return id;
    },
    []
  );

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toasts, toast, dismiss }}>
      {children}
      <div className="fixed top-5 right-5 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} dismiss={dismiss} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

function ToastItem({ toast, dismiss }) {
  const typeStyles = {
    success: "border-emerald-500 bg-emerald-500/10 text-emerald-300",
    error: "border-red-500 bg-red-500/10 text-red-300",
    warning: "border-amber-500 bg-amber-500/10 text-amber-300",
    info: "border-blue-500 bg-blue-500/10 text-blue-300",
  };
  const icons = {
    success: <CheckCircle className="w-4 h-4" />,
    error: <AlertCircle className="w-4 h-4" />,
    warning: <AlertTriangle className="w-4 h-4" />,
    info: <Info className="w-4 h-4" />,
  };
  return (
    <div
      className={`glass rounded-xl p-4 px-5 shadow-card flex items-start gap-3 min-w-[320px] pointer-events-auto animate-in fade-in slide-in-from-right-2 duration-300 ${
        typeStyles[toast.type]
      }`}
    >
      <div className="flex-shrink-0 mt-0.5">{icons[toast.type]}</div>
      <div className="flex-1">
        {toast.title && <div className="text-sm font-semibold text-slate-100">{toast.title}</div>}
        {toast.description && (
          <div className="text-xs text-slate-400 mt-0.5">{toast.description}</div>
        )}
      </div>
      <button
        onClick={() => dismiss(toast.id)}
        className="flex-shrink-0 text-slate-500 hover:text-slate-300 transition-colors p-1"
        aria-label="Dismiss"
      >
        <X className="w-3 h-3" />
      </button>
    </div>
  );
}

function CheckCircle() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
    </svg>
  );
}
function AlertCircle() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3" />
    </svg>
  );
}
function AlertTriangle() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3" />
    </svg>
  );
}
function Info() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );
}
function X() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => {
    if (typeof window === "undefined") return null;
    if (localStorage.getItem("ts_logged_out") === "true") return null;
    return localStorage.getItem("ts_token") || null;
  });

  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Synchronize authenticated user profile from backend
  useEffect(() => {
    let isMounted = true;

    async function loadUser() {
      const currentToken = localStorage.getItem("ts_token");
      if (!currentToken || localStorage.getItem("ts_logged_out") === "true") {
        if (isMounted) {
          setUser(null);
          setLoading(false);
        }
        return;
      }

      try {
        const userData = await authApi.getMe();
        if (isMounted) {
          setUser(userData);
          setLoading(false);
        }
      } catch (err) {
        if (isMounted) {
          setUser(null);
          setToken(null);
          localStorage.removeItem("ts_token");
          localStorage.removeItem("ts_refresh_token");
          setLoading(false);
        }
      }
    }

    loadUser();

    // Listen for global logout events from api interceptor
    const handleGlobalLogout = () => {
      setToken(null);
      setUser(null);
    };
    window.addEventListener("ts_auth_logout", handleGlobalLogout);

    return () => {
      isMounted = false;
      window.removeEventListener("ts_auth_logout", handleGlobalLogout);
    };
  }, [token]);

  const login = useCallback(async (email, password) => {
    const data = await authApi.login({ email, password });
    localStorage.removeItem("ts_logged_out");
    localStorage.setItem("ts_token", data.access_token);
    localStorage.setItem("ts_refresh_token", data.refresh_token);
    setToken(data.access_token);
    setUser(data.user);
    return data.user;
  }, []);

  const register = useCallback(async (name, email, password) => {
    const data = await authApi.register({ email, password, full_name: name });
    localStorage.removeItem("ts_logged_out");
    localStorage.setItem("ts_token", data.access_token);
    localStorage.setItem("ts_refresh_token", data.refresh_token);
    setToken(data.access_token);
    setUser(data.user);
    return data.user;
  }, []);

  const handleOAuthSuccess = useCallback(async (accessToken, refreshToken) => {
    localStorage.removeItem("ts_logged_out");
    localStorage.setItem("ts_token", accessToken);
    if (refreshToken) {
      localStorage.setItem("ts_refresh_token", refreshToken);
    }
    setToken(accessToken);
    try {
      const userData = await authApi.getMe();
      setUser(userData);
      return userData;
    } catch (e) {
      return null;
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch (_) {
      // Best effort server logout
    } finally {
      setToken(null);
      setUser(null);
      localStorage.removeItem("ts_token");
      localStorage.removeItem("ts_refresh_token");
      localStorage.setItem("ts_logged_out", "true");
    }
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        login,
        register,
        handleOAuthSuccess,
        logout,
        isAuthenticated: !!token && !!user,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
