import { NavLink } from "react-router-dom";
import { LayoutDashboard, Search, FileText, ShieldAlert, Bell, Settings, LogOut, Mail, Users, ShieldCheck, Zap } from "lucide-react";
import { useNavigate } from "react-router-dom";

const ITEMS = [
  { key: "dashboard", label: "Dashboard", icon: LayoutDashboard, to: "/dashboard" },
  { key: "scan", label: "Scan URL", icon: Search, to: "/scan" },
  { key: "reports", label: "Scan Reports", icon: FileText, to: "/reports" },
  { key: "community", label: "Community Reports", icon: Users, to: "/community" },
  { key: "watchlist", label: "Watchlist", icon: ShieldCheck, to: "/watchlist" },
  { key: "settings", label: "Settings", icon: Settings, to: "/settings" },
];

export function Sidebar({ className }) {
  return (
    <aside className={cn("fixed left-0 top-0 bottom-0 w-64 glass border-r border-white/5 flex flex-col z-40", className)}>
      <div className="px-6 py-5 flex items-center gap-2">
        <div className="w-8 h-8 rounded-lg bg-blue-600/20 flex items-center justify-center text-blue-400 font-bold">
          TS
        </div>
        <span className="text-lg font-bold text-slate-100 tracking-tight">TrustShield</span>
      </div>
      <nav className="flex-1 px-3 py-4 space-y-1">
        {ITEMS.map((item) => (
          <NavLink
            key={item.key}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-colors ${
                isActive
                  ? "bg-blue-600/10 text-blue-400 border-r-2 border-blue-500"
                  : "text-slate-500 hover:bg-white/5 hover:text-slate-300"
              }`
            }
            end={item.key === "dashboard"}
          >
            <item.icon className="w-5 h-5" />
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="px-6 py-4 border-t border-white/5">
        <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium text-red-400 hover:bg-red-500/5 transition-colors">
          <LogOut className="w-4 h-4" />
          Sign out
        </button>
      </div>
    </aside>
  );
}

export function TopBar({ onSearch, onNotify, onProfile, onThemeToggle }) {
  return (
    <header className="glass border-b border-white/5 flex items-center justify-between px-6 py-3 z-30 sticky top-0">
      <div className="flex items-center gap-3">
        <button className="md:hidden text-slate-400 hover:text-white p-2">
          <span className="sr-only">Open menu</span>
          <svg className="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <div className="hidden md:flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-blue-600/20 flex items-center justify-center text-blue-400 font-bold">TS</div>
          <span className="font-bold text-slate-100 text-sm tracking-tight">TrustShield</span>
        </div>
        <div className="flex-1 max-w-xl px-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Scan a URL..."
              className="w-full rounded-xl border border-white/10 bg-white/5 pl-9 pr-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
              onKeyDown={(e) => e.key === "Enter" && onSearch(e.target.value)}
            />
          </div>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <button
          onClick={onThemeToggle}
          className="p-2 rounded-lg text-slate-400 hover:bg-white/5 hover:text-white transition-colors"
          aria-label="Toggle theme"
        >
          <svg className="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 3c4.971 0 9.014 3.53 9.014 7.938c0 1.807-.622 3.47-1.646 4.718zM14 10a2 2 0 11-4 0 2 2 0 014 0z" />
          </svg>
        </button>
        <button onClick={onNotify} className="relative p-2 rounded-lg text-slate-400 hover:bg-white/5 hover:text-white transition-colors" aria-label="Notifications">
          <Bell className="w-5 h-5" />
        </button>
        <button onClick={onProfile} className="flex items-center gap-2 px-3 py-1.5 rounded-xl border border-white/10 bg-white/5 text-sm font-medium text-slate-200 hover:bg-white/10 transition-colors">
          <div className="w-7 h-7 rounded-full bg-blue-600/30 flex items-center justify-center text-blue-400 text-xs font-bold">A</div>
        </button>
      </div>
    </header>
  );
}

export function BottomNav() {
  const navigate = useNavigate();
  const TABS = [
    { key: "dashboard", label: "Dashboard", icon: LayoutDashboard, to: "/dashboard" },
    { key: "scan", label: "Scan", icon: Search, to: "/scan" },
    { key: "community", label: "Community", icon: Users, to: "/community" },
    { key: "profile", label: "Profile", icon: Zap, to: "/profile" },
  ];
  return (
    <nav className="fixed bottom-0 left-0 right-0 h-14 glass border-t border-white/5 flex justify-around items-center z-40">
      {TABS.map((tab) => (
        <button
          key={tab.key}
          onClick={() => navigate(tab.to)}
          className="flex flex-col items-center gap-1 px-3 py-1.5 text-xs transition-colors"
        >
          <tab.icon className="w-5 h-5 text-slate-500" />
          <span className="text-[10px] text-slate-500">{tab.label}</span>
        </button>
      ))}
    </nav>
  );
}
