import { cn } from "@/utils/cn";
import { forwardRef } from "react";

export const Input = forwardRef(({ className, type, ...props }, ref) => (
  <input
    type={type}
    ref={ref}
    className={cn(
      "flex-1 block w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200 placeholder-slate-500 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/60 disabled:opacity-50 disabled:cursor-not-allowed",
      className
    )}
    {...props}
  />
));
Input.displayName = "Input";

export const Textarea = forwardRef(({ className, ...props }, ref) => (
  <textarea
    ref={ref}
    className={cn(
      "block w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200 placeholder-slate-500 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/60 disabled:opacity-50 disabled:cursor-not-allowed",
      className
    )}
    {...props}
  />
));
Textarea.displayName = "Textarea";

export const Select = forwardRef(({ className, children, ...props }, ref) => (
  <select
    ref={ref}
    className={cn(
      "flex-1 block w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/60 disabled:opacity-50 disabled:cursor-not-allowed appearance-none",
      className
    )}
    {...props}
  >
    {children}
  </select>
));
Select.displayName = "Select";

export const Label = ({ children, className }) => (
  <label className={cn("block text-sm font-medium text-slate-300 mb-1.5", className)}>{children}</label>
);
