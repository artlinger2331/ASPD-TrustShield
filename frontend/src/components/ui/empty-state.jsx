import { ShieldAlert } from "lucide-react";

export function EmptyState({ title, description, icon: Icon = ShieldAlert, action, actionLabel }) {
  return (
    <div className="glass rounded-2xl p-12 text-center">
      <div className="w-16 h-16 rounded-full bg-white/5 flex items-center justify-center mx-auto mb-4 text-slate-500">
        <Icon className="w-8 h-8" />
      </div>
      <h3 className="text-lg font-semibold text-slate-100 mb-2">{title}</h3>
      <p className="text-slate-500 text-sm max-w-xs mx-auto mb-6">{description}</p>
      {action && (
        <button className="bg-blue-600 text-white px-5 py-2 rounded-xl text-sm font-medium hover:bg-blue-500 transition-colors">
          {actionLabel}
        </button>
      )}
    </div>
  );
}
