import { cn } from "@/utils/cn";

export function Button({ className, variant = "primary", size = "md", disabled, loading, children, ...props }) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-xl font-medium transition-all duration-200 disabled:opacity-60 disabled:pointer-events-none focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-navy-900";
  const variants = {
    primary:
      "bg-blue-600 text-white hover:bg-blue-500 focus:ring-blue-500 shadow-[0_0_0_1px_rgba(59,130,246,0.2)]",
    secondary:
      "bg-white/5 text-slate-200 border border-white/10 hover:bg-white/10 focus:ring-blue-500",
    outline:
      "border border-white/10 text-slate-300 hover:bg-white/5 focus:ring-blue-500",
    ghost:
      "text-slate-400 hover:text-white hover:bg-white/5 focus:ring-blue-500",
    danger:
      "bg-red-600 text-white hover:bg-red-500 focus:ring-red-500 shadow-[0_0_0_1px_rgba(239,68,68,0.2)]",
    success:
      "bg-emerald-600 text-white hover:bg-emerald-500 focus:ring-emerald-500",
  };
  const sizes = {
    sm: "px-3 py-1.5 text-sm",
    md: "px-5 py-2.5 text-sm",
    lg: "px-7 py-3.5 text-base",
  };
  return (
    <button
      className={cn(base, variants[variant], sizes[size], className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <svg className="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
      )}
      {children}
    </button>
  );
}
