import { useEffect, useState, useRef } from "react";
import { cn } from "@/utils/cn";

export function RiskGauge({ score, size = 220, className }) {
  const [percent, setPercent] = useState(0);
  const [color, setColor] = useState("#22d3ee");

  useEffect(() => {
    let start = 0;
    const end = score;
    const dur = 900;
    const startTime = performance.now();
    function frame(now) {
      const t = Math.min(1, (now - startTime) / dur);
      const cur = start + (end - start) * t;
      setPercent(cur);
      if (t < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }, [score]);

  useEffect(() => {
    setColor(score <= 30 ? "#10b981" : score <= 50 ? "#f59e0b" : score <= 75 ? "#f97316" : "#ef4444");
  }, [score]);

  const cx = size / 2;
  const cy = size / 2;
  const r = (size / 2) * 0.78;
  const strokeWidth = size * 0.09;
  const startAngle = -135;
  const endAngle = 45;
  const arc = endAngle - startAngle;
  const endDash = (percent / 100) * arc;
  const circumference = (arc / 360) * 2 * Math.PI * r;

  const gradientId = "gaugeGradient";

  return (
    <div className={cn("relative flex flex-col items-center", className)}>
      <svg width={size} height={size * 0.62} className="block">
        <defs>
          <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#3b82f6" />
            <stop offset="40%" stopColor="#22d3ee" />
            <stop offset="70%" stopColor="#f59e0b" />
            <stop offset="100%" stopColor="#ef4444" />
          </linearGradient>
        </defs>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="white/5" strokeWidth={strokeWidth} />
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          style={{
            strokeDasharray: `${circumference} ${circumference}`,
            strokeDashoffset: circumference - (endDash / arc) * circumference,
            transition: "stroke-dashoffset 0.8s ease-out, stroke 0.3s",
          }}
        />
      </svg>
      <div className="mt-6 flex flex-col items-center">
        <span className="text-3xl font-bold text-slate-100">{Math.round(percent)}</span>
        <span className="text-xs text-slate-500 mt-1 tracking-wide uppercase">risk score</span>
      </div>
    </div>
  );
}
