import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Mail, ArrowRight, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";

export default function ForgotPassword() {
  const navigate = useNavigate();
  const [sent, setSent] = useState(false);
  const [email, setEmail] = useState("");

  if (sent) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-navy-900 px-4">
        <Card className="w-full max-w-md p-8 text-center">
          <div className="w-12 h-12 rounded-full bg-emerald-500/10 flex items-center justify-center mx-auto mb-6 text-emerald-400">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <CardTitle className="text-xl font-bold text-slate-100">Reset link sent</CardTitle>
          <CardDescription>
            We&apos;ve emailed a reset link to {email}. Please check your inbox.
          </CardDescription>
          <div className="mt-8">
            <Button onClick={() => navigate("/login")} className="w-full">
              Back to sign in
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-navy-900 px-4">
      <Card className="w-full max-w-md p-8">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-bold text-slate-100">Forgot password?</CardTitle>
          <CardDescription>Enter your email and we&apos;ll send a reset link.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setSent(true);
            }}
            className="space-y-4"
          >
            <div className="relative">
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
            <Button type="submit" className="w-full py-3 text-lg">
              Send reset link <ArrowRight className="w-4 h-4 ml-2" />
            </Button>
          </form>
          <p className="text-center text-xs text-slate-500 mt-6">
            Remember your password?{" "}
            <Link to="/login" className="text-blue-400 font-medium hover:underline">Sign in</Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
