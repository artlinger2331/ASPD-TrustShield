import { Link, useNavigate } from "react-router-dom";
import { User, ShieldCheck, Settings, LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/hooks/useAuth";

export default function Profile() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="min-h-screen flex flex-col">
      <div className="flex-1 overflow-y-auto py-6 px-4 sm:px-6 lg:px-8 max-w-2xl mx-auto">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Profile</h1>
            <p className="text-sm text-slate-500">Manage your account settings.</p>
          </div>
        </div>

        <Card className="mb-6">
          <CardContent className="flex flex-col md:flex-row items-center gap-6 p-6">
            <div className="w-20 h-20 rounded-2xl bg-blue-600/20 flex items-center justify-center text-blue-400 text-2xl font-bold border border-blue-500/30">
              <User className="w-10 h-10" />
            </div>
            <div className="flex-1 space-y-2">
              {!user ? (
                <>
                  <Skeleton className="h-6 w-48 rounded-lg bg-white/5" />
                  <Skeleton className="h-4 w-64 rounded bg-white/5" />
                  <Skeleton className="h-4 w-24 rounded-full bg-cyan-500/10" />
                </>
              ) : (
                <>
                  <h2 className="text-lg font-bold text-slate-100">{user?.full_name || user?.name || "Security Analyst"}</h2>
                  <p className="text-sm text-slate-400">{user?.email || "No email"}</p>
                  <div className="flex items-center gap-2 mt-2">
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 uppercase">
                      {user?.role || "user"}
                    </span>
                    {user?.is_active && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        ACTIVE
                      </span>
                    )}
                  </div>
                </>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Account settings</CardTitle>
            <CardDescription>Update your preferences.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between py-4 border-b border-white/5">
              <div>
                <div className="text-sm font-medium text-slate-200">Email notifications</div>
                <div className="text-xs text-slate-500">Receive scan and alert notifications</div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" defaultChecked className="peer sr-only" />
                <div className="w-9 h-5 rounded-full bg-white/5 border border-white/10 peer-checked:bg-blue-600 peer-checked:border-blue-600 transition-colors" />
                <div className="w-3 h-3 rounded-full bg-white transform translate-x-1 peer-checked:translate-x-5 shadow transition-all" />
              </label>
            </div>
            <div className="flex items-center justify-between py-4 border-b border-white/5">
              <div>
                <div className="text-sm font-medium text-slate-200">Weekly threat digest</div>
                <div className="text-xs text-slate-500">Weekly summary of new threats</div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" defaultChecked className="peer sr-only" />
                <div className="w-9 h-5 rounded-full bg-white/5 border border-white/10 peer-checked:bg-blue-600 peer-checked:border-blue-600 transition-colors" />
                <div className="w-3 h-3 rounded-full bg-white transform translate-x-1 peer-checked:translate-x-5 shadow transition-all" />
              </label>
            </div>
            <div className="pt-4">
              <Button variant="danger" onClick={handleLogout} className="w-full">
                <LogOut className="w-4 h-4 mr-2" /> Sign out
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
