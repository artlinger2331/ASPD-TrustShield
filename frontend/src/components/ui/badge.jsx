import { cn } from "@/utils/cn";
import { severityColor } from "@/utils/formatters";

export function Badge({ className, variant, children }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        severityColor(variant),
        className
      )}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, children }) {
  return <Badge variant={severity}>{children}</Badge>;
}

export function StatusBadge({ status }) {
  const map = {
    pending: "bg-amber-500/10 border-amber-500/30 text-amber-400",
    verified: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
    "false-positive": "bg-slate-500/10 border-slate-500/30 text-slate-400",
  };
  return (
    <span className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${map[status]}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

export function VerdictBadge({ verdict }) {
  const map = {
    safe: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400",
    suspicious: "bg-amber-500/10 border-amber-500/20 text-amber-400",
    "high-risk": "bg-orange-500/10 border-orange-500/20 text-orange-400",
    dangerous: "bg-red-500/10 border-red-500/20 text-red-400",
  };
  return (
    <span className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wider ${map[verdict]}`}>
      {verdict.charAt(0).toUpperCase() + verdict.slice(1).replace("-", " ")}
    </span>
  );
}

export function HeaderCheck({ status }) {
  const map = {
    pass: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400",
    warning: "bg-amber-500/10 border-amber-500/30 text-amber-400",
    fail: "bg-red-500/10 border-red-500/30 text-red-400",
    "n-a": "bg-slate-700/30 border-slate-600/50 text-slate-500",
  };
  return (
    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${map[status]}`}>
      {status.toUpperCase()}
    </span>
  );
}
