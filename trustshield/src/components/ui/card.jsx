import { cn } from "@/utils/cn";
import { forwardRef } from "react";

export const Card = forwardRef(({ className, children, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("glass rounded-2xl p-6", className)}
    {...props}
  >
    {children}
  </div>
));
Card.displayName = "Card";

export const CardHeader = ({ children, className }) => (
  <div className={cn("flex flex-col space-y-1.5 pb-2", className)}>{children}</div>
);

export const CardTitle = ({ className, children }) => (
  <h3 className={cn("text-lg font-semibold text-slate-100 tracking-tight", className)}>{children}</h3>
);

export const CardDescription = ({ className, children }) => (
  <p className={cn("text-sm text-slate-500", className)}>{children}</p>
);

export const CardContent = ({ className, children }) => (
  <div className={cn("pt-2", className)}>{children}</div>
);

export const CardFooter = ({ className, children }) => (
  <div className={cn("mt-6 flex items-center gap-2 pt-4 border-t border-white/5", className)}>{children}</div>
);
