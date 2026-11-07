import { useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { Shield, ArrowRight, CheckCircle2, User, Key, ExternalLink } from "lucide-react";

export default function ProviderConsent() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const provider = (searchParams.get("provider") || "google").toLowerCase();
  const state = searchParams.get("state") || "";

  const isGoogle = provider === "google";

  const [selectedEmail, setSelectedEmail] = useState(
    isGoogle ? "pritam.mondal@gmail.com" : "developer.pritam@github.com"
  );
  const [selectedName, setSelectedName] = useState(
    isGoogle ? "Pritam Mondal" : "Pritam Mondal (GitHub)"
  );
  const [customMode, setCustomMode] = useState(false);

  const handleAuthorize = () => {
    const callbackBase = isGoogle
      ? "http://localhost:8000/api/v1/auth/oauth/google/callback"
      : "http://localhost:8000/api/v1/auth/oauth/github/callback";

    const params = new URLSearchParams({
      code: isGoogle ? "dev_google_mock_code" : "dev_github_mock_code",
      email: selectedEmail,
      name: selectedName,
      state: state,
    });

    window.location.href = `${callbackBase}?${params.toString()}`;
  };

  return (
    <div className="min-h-screen bg-[#070b14] flex flex-col items-center justify-center p-4 relative font-sans">
      {/* Background glow */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      {/* Developer Environment Alert Banner */}
      <div className="w-full max-w-md mb-4 bg-cyan-950/40 border border-cyan-500/30 rounded-xl p-3 text-xs text-cyan-200 flex items-start gap-2.5 backdrop-blur-md">
        <Key className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
        <div>
          <span className="font-semibold text-cyan-300">OAuth Developer Simulation:</span>
          <p className="text-slate-300 mt-0.5">
            Redirected here because <code className="text-cyan-300 bg-black/40 px-1 py-0.5 rounded">{isGoogle ? "GOOGLE_CLIENT_ID" : "GITHUB_CLIENT_ID"}</code> is not yet configured in <code className="text-cyan-300 bg-black/40 px-1 py-0.5 rounded">backend/.env</code>.
          </p>
        </div>
      </div>

      {/* Provider Card */}
      <div className="w-full max-w-md bg-navy-800/95 border border-white/10 rounded-2xl p-7 shadow-2xl backdrop-blur-xl relative z-10 text-slate-100">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center pb-6 border-b border-white/5">
          {isGoogle ? (
            <div className="w-12 h-12 rounded-full bg-white flex items-center justify-center shadow-md mb-3">
              <svg className="w-7 h-7" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
            </div>
          ) : (
            <div className="w-12 h-12 rounded-full bg-[#181717] border border-white/20 flex items-center justify-center shadow-md mb-3">
              <svg className="w-8 h-8 fill-white" viewBox="0 0 24 24">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
              </svg>
            </div>
          )}

          <h1 className="text-xl font-bold tracking-tight text-white">
            {isGoogle ? "Sign in with Google" : "Authorize TrustShield"}
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            to continue to <span className="text-cyan-400 font-medium">TrustShield SecOps</span>
          </p>
        </div>

        {/* Content & Account Selection */}
        <div className="py-5 space-y-4">
          <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">
            Choose an account
          </div>

          {!customMode ? (
            <div className="space-y-2">
              <button
                type="button"
                onClick={() => {}}
                className="w-full flex items-center justify-between p-3 rounded-xl bg-white/5 border border-cyan-500/30 hover:bg-white/10 transition-all text-left group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center text-white font-bold text-sm shadow-inner">
                    {selectedName.charAt(0)}
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-slate-200 group-hover:text-white">
                      {selectedName}
                    </div>
                    <div className="text-xs text-slate-400">{selectedEmail}</div>
                  </div>
                </div>
                <CheckCircle2 className="w-5 h-5 text-cyan-400" />
              </button>

              <button
                type="button"
                onClick={() => setCustomMode(true)}
                className="w-full text-left px-3 py-2 text-xs text-blue-400 hover:text-blue-300 hover:underline transition-colors"
              >
                + Use a different account
              </button>
            </div>
          ) : (
            <div className="space-y-3 bg-white/5 p-4 rounded-xl border border-white/5">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Full Name</label>
                <input
                  type="text"
                  value={selectedName}
                  onChange={(e) => setSelectedName(e.target.value)}
                  className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-400"
                  placeholder="Your Name"
                />
              </div>
              <div>
                <label className="text-xs text-slate-400 block mb-1">Email Address</label>
                <input
                  type="email"
                  value={selectedEmail}
                  onChange={(e) => setSelectedEmail(e.target.value)}
                  className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-400"
                  placeholder="your.email@example.com"
                />
              </div>
              <button
                type="button"
                onClick={() => setCustomMode(false)}
                className="text-xs text-slate-400 hover:text-white underline"
              >
                Done
              </button>
            </div>
          )}

          {/* Permissions explanation */}
          <div className="text-xs text-slate-400 leading-relaxed bg-black/20 p-3 rounded-lg border border-white/5">
            To continue, {isGoogle ? "Google" : "GitHub"} will share your name, email address, language preference, and profile picture with TrustShield.
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3 pt-3 border-t border-white/5">
          <button
            type="button"
            onClick={() => navigate("/login")}
            className="flex-1 py-2.5 px-4 rounded-xl border border-white/10 text-slate-300 hover:bg-white/5 text-sm font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleAuthorize}
            className={`flex-1 py-2.5 px-4 rounded-xl text-sm font-semibold text-white shadow-lg transition-all flex items-center justify-center gap-2 ${
              isGoogle
                ? "bg-blue-600 hover:bg-blue-500 shadow-blue-600/30"
                : "bg-emerald-600 hover:bg-emerald-500 shadow-emerald-600/30"
            }`}
          >
            <span>{isGoogle ? "Continue" : "Authorize"}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

