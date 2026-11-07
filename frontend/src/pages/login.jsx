import { useState, useEffect } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Mail, Lock, Eye, EyeOff, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { useAuth, useToast } from "@/hooks/useAuth";

function GoogleIcon({ className = "w-4 h-4 mr-2" }) {
  return (
    <svg className={className} viewBox="0 0 24 24">
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
  );
}

function GitHubIcon({ className = "w-4 h-4 mr-2" }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 24 24">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

export default function Login() {
  const { login } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  useEffect(() => {
    const errorMsg = searchParams.get("error");
    if (errorMsg) {
      toast({
        title: "Authentication Error",
        description: decodeURIComponent(errorMsg),
        type: "error",
      });
    }
  }, [searchParams, toast]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email.trim() || !password) {
      toast({
        title: "Missing fields",
        description: "Please enter both email and password.",
        type: "error",
      });
      return;
    }
    setLoading(true);
    try {
      await login(email.trim(), password);
      toast({
        title: "Welcome back",
        description: "Successfully authenticated with TrustShield SecOps.",
        type: "success",
      });
      navigate("/dashboard");
    } catch (err) {
      toast({
        title: "Authentication Failed",
        description: err.message || "Invalid email or password. Please try again.",
        type: "error",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleOAuthLogin = (provider) => {
    window.location.href = `http://localhost:8000/api/v1/auth/oauth/${provider}`;
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-navy-900 px-4 relative overflow-hidden">
      {/* Liquid background glow effect */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/4 left-1/3 w-[400px] h-[400px] bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none" />

      <Card className="w-full max-w-md p-8 relative z-10 glass border border-white/10 shadow-2xl backdrop-blur-2xl">
        <CardHeader className="text-center pb-2">
          <CardTitle className="text-2xl font-bold text-slate-100 tracking-tight">Welcome back</CardTitle>
          <CardDescription className="text-slate-400 text-sm">Sign in to your TrustShield security account</CardDescription>
        </CardHeader>

        <CardContent className="space-y-5 pt-4">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="relative">
              <Label className="text-xs font-semibold text-slate-300">Email address</Label>
              <div className="relative mt-1">
                <Input
                  type="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="pl-10 bg-navy-900/60 border-white/10 text-white placeholder:text-slate-500 focus:border-cyan-400"
                />
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
              </div>
            </div>

            <div className="relative">
              <Label className="text-xs font-semibold text-slate-300">Password</Label>
              <div className="relative mt-1">
                <Input
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-10 pr-10 bg-navy-900/60 border-white/10 text-white placeholder:text-slate-500 focus:border-cyan-400"
                />
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white transition-colors"
                  aria-label="Toggle password visibility"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs pt-1">
              <label className="flex items-center gap-1.5 cursor-pointer text-slate-400 hover:text-white transition-colors">
                <input type="checkbox" className="w-3.5 h-3.5 rounded border-white/10 bg-white/5 text-blue-600 focus:ring-0" />
                Remember me
              </label>
              <Link to="/forgot-password" className="text-cyan-400 hover:text-cyan-300 transition-colors">
                Forgot password?
              </Link>
            </div>

            <Button type="submit" loading={loading} className="w-full py-2.5 text-base font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/30 transition-all">
              Sign in <ArrowRight className="w-4 h-4 ml-2" />
            </Button>
          </form>

          <div className="relative my-4">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t border-white/10"></span>
            </div>
            <div className="relative flex justify-center text-xs">
              <span className="px-3 bg-navy-800/90 text-slate-400 font-medium">Or continue with</span>
            </div>
          </div>

          <div className="flex gap-3">
            <Button
              type="button"
              variant="outline"
              onClick={() => handleOAuthLogin("google")}
              className="flex-1 border-white/10 bg-white/5 hover:bg-white/10 text-slate-200 hover:text-white transition-all py-2.5 flex items-center justify-center font-medium"
            >
              <GoogleIcon className="w-4 h-4 mr-2" /> Google
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => handleOAuthLogin("github")}
              className="flex-1 border-white/10 bg-white/5 hover:bg-white/10 text-slate-200 hover:text-white transition-all py-2.5 flex items-center justify-center font-medium"
            >
              <GitHubIcon className="w-4 h-4 mr-2" /> GitHub
            </Button>
          </div>

          <p className="text-center text-xs text-slate-400 mt-5">
            Don't have an account?{" "}
            <Link to="/register" className="text-cyan-400 font-semibold hover:text-cyan-300 hover:underline transition-colors">
              Create one
            </Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
