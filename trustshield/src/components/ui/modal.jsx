import { X } from "lucide-react";

export function Modal({ open, onClose, children, className, title }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        className={cn(
          "relative w-full max-w-lg mx-4 glass rounded-2xl p-0 shadow-card transform transition-all",
          className
        )}
        role="dialog"
        aria-modal="true"
      >
        {title && (
          <div className="px-6 py-4 border-b border-white/5 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-slate-100">{title}</h3>
            <button onClick={onClose} className="text-slate-400 hover:text-white p-1">
              <X className="w-5 h-5" />
            </button>
          </div>
        )}
        <div className="px-6 py-4">{children}</div>
      </div>
    </div>
  );
}
