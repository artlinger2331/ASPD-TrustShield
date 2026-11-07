import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Mail, Lock, Eye, EyeOff, ArrowRight, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { useAuth, useToast } from "@/hooks/useAuth";

export default function Login() {
  const { login } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

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

  return (
    <div className="min-h-screen flex items-center justify-center bg-navy-900 px-4">
      <Card className="w-full max-w-md p-8">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-bold text-slate-100">Welcome back</CardTitle>
          <CardDescription>Sign in to your TrustShield account</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <Label>Email address</Label>
              <Input
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="pl-10"
              />
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            </div>
            <div className="relative">
              <Label>Password</Label>
              <Input
                type={showPassword ? "text" : "password"}
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white"
                aria-label="Toggle password visibility"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <div className="flex items-center justify-between text-xs">
              <label className="flex items-center gap-1.5 cursor-pointer text-slate-400 hover:text-white">
                <input type="checkbox" className="w-3 h-3 rounded border-white/10 bg-white/5 text-blue-600" />
                Remember me
              </label>
              <Link to="/forgot-password" className="text-blue-400 hover:underline">Forgot password?</Link>
            </div>
            <Button type="submit" loading={loading} className="w-full py-3 text-lg">
              Sign in <ArrowRight className="w-4 h-4 ml-2" />
            </Button>
          </form>
          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t border-white/5"></span>
            </div>
            <div className="relative flex justify-center text-xs">
              <span className="px-2 bg-navy-800 text-slate-500">Or continue with</span>
            </div>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" className="flex-1">
              <User className="w-4 h-4 mr-2" /> Google
            </Button>
            <Button variant="outline" className="flex-1">
              <User className="w-4 h-4 mr-2" /> GitHub
            </Button>
          </div>
          <p className="text-center text-xs text-slate-500 mt-4">
            Don't have an account?{" "}
            <Link to="/register" className="text-blue-400 font-medium hover:underline">Create one</Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
