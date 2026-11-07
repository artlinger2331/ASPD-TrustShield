import { cn } from "@/utils/cn";

const STEPS = [
  "Checking domain reputation",
  "Analyzing page content",
  "Checking redirects",
  "Validating HTTPS certificate",
  "Checking security headers",
  "Comparing threat intelligence feeds",
  "Calculating trust score",
];

export function ProgressStepper({ activeStep, completed = false }) {
  return (
    <div className="glass rounded-2xl p-6 max-w-md mx-auto space-y-6">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-slate-300">Scan in progress</span>
        {completed ? (
          <span className="text-xs text-emerald-400 font-medium">Completed</span>
        ) : (
          <span className="text-xs text-slate-500">{activeStep + 1} / {STEPS.length}</span>
        )}
      </div>
      <div className="space-y-2.5">
        {STEPS.map((step, i) => {
          const done = i < activeStep;
          const current = i === activeStep;
          return (
            <div key={i} className="flex items-center gap-3 group">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all ${done ? "bg-emerald-600 text-white border-emerald-600" : current ? "bg-blue-600 text-white border-blue-600 animate-pulse" : "bg-white/5 text-slate-600 border border-white/10"}`}
              >
                {done ? (
                  <svg className="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" d="M5 13l4 4L19 7" />
                  </svg>
                ) : current ? (
                  <svg className="w-4 h-4 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                ) : (
                  i + 1
                )}
              </div>
              <div className="flex-1">
                <div className={cn("text-sm transition-colors", done ? "text-slate-300" : current ? "text-blue-400 font-medium" : "text-slate-600")}>
                  {step}
                </div>
                {current && (
                  <div className="h-1.5 w-full rounded-full bg-white/5 mt-1.5 overflow-hidden">
                    <div className="h-full bg-blue-500 w-[70%] animate-pulse" />
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
