import { useState } from "react";
import { Key, ExternalLink, X, Shield, ArrowRight, CheckCircle2 } from "lucide-react";
import { authApi } from "@/utils/api";
import { useToast } from "@/hooks/useAuth";

export default function OAuthSetupModal({ provider = "google", isOpen, onClose, onSuccess }) {
  const { toast } = useToast();
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const isGoogle = provider === "google";
  const title = isGoogle ? "Google Cloud OAuth Setup" : "GitHub OAuth App Setup";
  const docsUrl = isGoogle
    ? "https://console.cloud.google.com/apis/credentials"
    : "https://github.com/settings/developers";
  const redirectUri = isGoogle
    ? "http://localhost:8000/api/v1/auth/oauth/google/callback"
    : "http://localhost:8000/api/v1/auth/oauth/github/callback";

  const handleSave = async (e) => {
    e.preventDefault();
    if (!clientId.trim() || !clientSecret.trim()) {
      toast({
        title: "Missing credentials",
        description: `Please enter both the Client ID and Client Secret from your ${isGoogle ? "Google Cloud" : "GitHub"} dashboard.`,
        type: "error",
      });
      return;
    }

    setLoading(true);
    try {
      const res = await authApi.configureOAuth({
        provider,
        client_id: clientId.trim(),
        client_secret: clientSecret.trim(),
      });

      toast({
        title: "Credentials Saved",
        description: `Redirecting directly to ${isGoogle ? "Google" : "GitHub"} sign-in...`,
        type: "success",
      });

      if (onSuccess) onSuccess();
      // Redirect to live provider authorization page
      window.location.href = res.auth_url || `http://localhost:8000/api/v1/auth/oauth/${provider}`;
    } catch (err) {
      toast({
        title: "Configuration Failed",
        description: err.message || "Could not save OAuth credentials.",
        type: "error",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-lg bg-navy-800 border border-white/10 rounded-2xl shadow-2xl p-6 text-slate-100 overflow-hidden">
        {/* Glow ambient background */}
        <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

        {/* Modal Header */}
        <div className="flex items-start justify-between pb-4 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
              <Key className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">{title}</h3>
              <p className="text-xs text-slate-400">
                Required for {isGoogle ? "Google" : "GitHub"} to securely fetch your browser's accounts
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Instructions */}
        <div className="my-4 p-3 bg-black/30 rounded-xl border border-white/5 space-y-2 text-xs text-slate-300">
          <div className="font-semibold text-cyan-400 flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5" />
            <span>Setup Instructions (1 minute):</span>
          </div>
          <ol className="list-decimal list-inside space-y-1.5 text-slate-300">
            <li>
              Open{" "}
              <a
                href={docsUrl}
                target="_blank"
                rel="noreferrer"
                className="text-cyan-400 hover:underline inline-flex items-center gap-0.5"
              >
                {isGoogle ? "Google Cloud Credentials" : "GitHub Developer Settings"}
                <ExternalLink className="w-3 h-3 ml-0.5" />
              </a>{" "}
              and create an <strong>OAuth 2.0 Web Client ID</strong>.
            </li>
            <li>
              Set the <strong>Authorized Redirect URI</strong> to:
              <div className="mt-1 font-mono text-[11px] bg-black/50 p-1.5 rounded border border-white/10 text-cyan-300 select-all">
                {redirectUri}
              </div>
            </li>
            <li>Paste the generated <strong>Client ID</strong> and <strong>Secret</strong> below:</li>
          </ol>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSave} className="space-y-3">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              {isGoogle ? "Google Client ID" : "GitHub Client ID"}
            </label>
            <input
              type="text"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              placeholder={isGoogle ? "xxxxxx-xxxxxx.apps.googleusercontent.com" : "Iv1.xxxxxx"}
              className="w-full px-3 py-2 bg-navy-900/80 border border-white/10 rounded-lg text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-400 font-mono text-xs"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              {isGoogle ? "Google Client Secret" : "GitHub Client Secret"}
            </label>
            <input
              type="password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              placeholder="GOCSPX-xxxxxxxxxxxxxxxx"
              className="w-full px-3 py-2 bg-navy-900/80 border border-white/10 rounded-lg text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-400 font-mono text-xs"
              required
            />
          </div>

          <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-white/10">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/30 transition-all flex items-center gap-1.5"
            >
              <span>{loading ? "Saving..." : `Connect ${isGoogle ? "Google" : "GitHub"}`}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
