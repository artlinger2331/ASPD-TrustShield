export function formatDate(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function formatDateTime(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function daysUntil(dateStr) {
  if (!dateStr) return null;
  const ms = new Date(dateStr).getTime() - Date.now();
  return Math.ceil(ms / (1000 * 60 * 60 * 24));
}

export function shortenUrl(url, len = 40) {
  if (!url) return "-";
  if (url.length <= len) return url;
  return url.slice(0, len - 1) + "\u2026";
}

export function riskColor(score) {
  if (score <= 30) return "text-emerald-400 border-emerald-500/20 bg-emerald-500/5";
  if (score <= 50) return "text-amber-400 border-amber-500/20 bg-amber-500/5";
  if (score <= 75) return "text-orange-400 border-orange-500/20 bg-orange-500/5";
  return "text-red-400 border-red-500/20 bg-red-500/5";
}

export function verdictLabel(score) {
  if (score <= 30) return "Likely Safe";
  if (score <= 50) return "Suspicious";
  if (score <= 75) return "High Risk";
  return "Dangerous / Likely Phishing";
}

export function severityColor(sev) {
  switch (sev) {
    case "Critical":
      return "bg-red-500/10 border-red-500/30 text-red-400";
    case "High":
      return "bg-orange-500/10 border-orange-500/30 text-orange-400";
    case "Medium":
      return "bg-amber-500/10 border-amber-500/30 text-amber-400";
    case "Low":
      return "bg-blue-500/10 border-blue-500/30 text-blue-400";
    case "Safe":
    default:
      return "bg-emerald-500/10 border-emerald-500/30 text-emerald-400";
  }
}
