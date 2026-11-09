import { useEffect, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Shield, CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";
import { useAuth, useToast } from "@/hooks/useAuth";

export default function OAuthCallback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { handleOAuthSuccess } = useAuth();
  const { toast } = useToast();
  const hasHandled = useRef(false);

  useEffect(() => {
    if (hasHandled.current) return;
    hasHandled.current = true;

    const token = searchParams.get("token");
    const refreshToken = searchParams.get("refresh_token");
    const provider = searchParams.get("provider") || "OAuth";
    const error = searchParams.get("error");

    if (error) {
      toast({
        title: "Authentication Failed",
        description: decodeURIComponent(error),
        type: "error",
      });
      navigate("/login", { replace: true });
      return;
    }

    if (!token) {
      toast({
        title: "Authentication Error",
        description: "No authorization token received from provider.",
        type: "error",
      });
      navigate("/login", { replace: true });
      return;
    }

    async function completeAuth() {
      try {
        const providerName =
          provider.toLowerCase() === "github"
            ? "GitHub"
            : provider.toLowerCase() === "google"
            ? "Google"
            : provider;

        await handleOAuthSuccess(token, refreshToken);

        toast({
          title: "Authentication Verified",
          description: `Successfully signed in via ${providerName} single sign-on.`,
          type: "success",
        });

        const storedRedirect = sessionStorage.getItem("ts_redirect_after_auth");
        const pendingUrl = sessionStorage.getItem("ts_pending_scan_url");
        sessionStorage.removeItem("ts_redirect_after_auth");
        sessionStorage.removeItem("ts_pending_scan_url");

        const targetDest =
          storedRedirect ||
          (pendingUrl ? `/scan?url=${encodeURIComponent(pendingUrl)}` : "/dashboard");

        navigate(targetDest, { replace: true });
      } catch (err) {
        toast({
          title: "Session Initialization Failed",
          description: err.message || "Could not retrieve user profile.",
          type: "error",
        });
        navigate("/login", { replace: true });
      }
    }

    completeAuth();
  }, [searchParams, navigate, handleOAuthSuccess, toast]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#070b14] px-4 relative overflow-hidden">
      {/* Background ambient security glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 left-1/2 -translate-x-1/2 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="relative z-10 w-full max-w-md p-8 rounded-2xl border border-white/10 bg-navy-800/80 backdrop-blur-xl shadow-2xl text-center">
        <div className="relative mx-auto w-16 h-16 mb-6 flex items-center justify-center">
          <div className="absolute inset-0 rounded-2xl bg-gradient-to-tr from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 animate-pulse" />
          <Shield className="w-8 h-8 text-cyan-400 relative z-10" />
          <Loader2 className="w-12 h-12 text-blue-500/60 animate-spin absolute" />
        </div>

        <h2 className="text-xl font-bold text-slate-100 tracking-wide mb-2">
          Verifying Security Assertion
        </h2>
        <p className="text-sm text-slate-400 mb-6 font-mono">
          Authenticating token & establishing SecOps session...
        </p>

        <div className="w-full bg-white/5 rounded-full h-1.5 overflow-hidden">
          <div className="bg-gradient-to-r from-blue-500 to-cyan-400 h-full w-2/3 animate-[pulse_1.5s_ease-in-out_infinite]" />
        </div>

        <div className="mt-4 flex items-center justify-center gap-2 text-xs text-slate-500 font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
          <span>TrustShield Zero-Trust Handshake</span>
        </div>
      </div>
    </div>
  );
}

