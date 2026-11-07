import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, Mail, FileImage, Send, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Label, Select, Textarea } from "@/components/ui/input";

const THREAT_TYPES = [
  "Phishing",
  "Scam",
  "Malware",
  "Fake Recruitment",
  "Impersonation",
  "Payment Fraud",
  "Other",
];
const SOURCES = ["Email", "SMS", "WhatsApp", "QR code", "Advertisement", "Other"];

export default function ReportWebsite() {
  const navigate = useNavigate();
  const [submitted, setSubmitted] = useState(false);
  const [reportId] = useState("TS-" + Math.floor(10000 + Math.random() * 90000));
  const [form] = useState({
    url: "",
    type: "Phishing",
    description: "",
    source: "Email",
    contact: "",
    consent: false,
  });

  if (submitted) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center py-12 px-4">
        <Card className="w-full max-w-md p-8 text-center">
          <div className="w-16 h-16 rounded-full bg-emerald-500/10 flex items-center justify-center mx-auto mb-6 text-emerald-400">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <h2 className="text-xl font-bold text-slate-100 mb-2">Report submitted</h2>
          <p className="text-sm text-slate-400 mb-6">
            Thank you for helping keep the community safe. Your report has been received and is under review.
          </p>
          <div className="bg-white/3 rounded-xl p-4 border border-white/5 mb-6">
            <div className="text-xs text-slate-500 uppercase mb-1">Report ID</div>
            <div className="text-sm font-mono font-bold text-slate-200">{reportId}</div>
          </div>
          <div className="flex gap-2">
            <Button onClick={() => navigate("/community")} className="flex-1">
              View community reports
            </Button>
            <Button variant="outline" onClick={() => navigate("/scan")} className="flex-1">
              Scan another URL
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <div className="flex-1 overflow-y-auto py-6 px-4 sm:px-6 lg:px-8 max-w-2xl mx-auto">
        <nav className="mb-6">
          <button
            onClick={() => navigate("/community")}
            className="flex items-center gap-2 text-xs text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-3 h-3" /> Back to reports
          </button>
        </nav>

        <Card className="p-6 md:p-8">
          <div className="mb-6">
            <h2 className="text-xl font-bold text-slate-100 mb-2">Report a suspicious website</h2>
            <p className="text-sm text-slate-500">
              Help us identify phishing, scams, and malicious sites. All reports are reviewed by our team.
            </p>
          </div>

          <form onSubmit={(e) => { e.preventDefault(); setSubmitted(true); }} className="space-y-5">
            <div>
              <Label>Website URL</Label>
              <Input
                type="url"
                placeholder="https://example.com"
                value={form.url}
                onChange={(e) => { form.url = e.target.value; }}
              />
            </div>

            <div>
              <Label>Threat type</Label>
              <Select value={form.type} onChange={(e) => { form.type = e.target.value; }}>
                {THREAT_TYPES.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </Select>
            </div>

            <div>
              <Label>Description</Label>
              <Textarea
                rows={4}
                placeholder="How did you encounter this link? What happened?"
                value={form.description}
                onChange={(e) => { form.description = e.target.value; }}
              />
            </div>

            <div>
              <Label>Screenshot upload (optional)</Label>
              <input
                type="file"
                accept="image/*"
                className="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-blue-600/20 file:text-blue-400 hover:file:bg-blue-600/30"
              />
            </div>

            <div>
              <Label>Source of link</Label>
              <Select value={form.source} onChange={(e) => { form.source = e.target.value; }}>
                {SOURCES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </Select>
            </div>

            <div>
              <Label>Optional contact email</Label>
              <Input type="email" placeholder="you@example.com" value={form.contact} onChange={(e) => { form.contact = e.target.value; }} />
            </div>

            <div className="flex items-start gap-3">
              <input
                id="consent"
                type="checkbox"
                checked={form.consent}
                onChange={(e) => { form.consent = e.target.checked; }}
                className="w-4 h-4 rounded border-white/10 bg-white/5 text-blue-600 focus:ring-blue-500"
              />
              <Label htmlFor="consent" className="text-sm leading-6">
                I consent to this report being used for security research and community threat intelligence.
              </Label>
            </div>

            <Button type="submit" className="w-full py-3 text-lg">
              <Send className="w-4 h-4 mr-2" /> Submit report
            </Button>
          </form>
        </Card>
      </div>
    </div>
  );
}
