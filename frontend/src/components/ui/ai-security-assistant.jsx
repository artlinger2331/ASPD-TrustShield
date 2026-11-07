import { useState, useRef, useEffect } from "react";
import { useLocation, useParams } from "react-router-dom";
import { Sparkles, X, Send, Bot, User, ShieldAlert, ChevronDown, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { assistantApi } from "@/utils/api";
import { cn } from "@/utils/cn";

export function AISecurityAssistant() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content:
        "Hello! I am your **TrustShield AI Security Assistant**. Ask me about phishing detection, what to do if you suspect credential theft, or how to interpret risk indicators.",
      suggested_actions: [
        "Why is this site dangerous?",
        "What should I do if I entered my password?",
        "Explain HSTS security header",
      ],
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  // Extract scan_id if user is currently on /report/:id
  const location = useLocation();
  const isReportPage = location.pathname.startsWith("/report/");
  const scanId = isReportPage ? location.pathname.split("/report/")[1] : null;

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

  const handleSend = async (textToSend) => {
    const query = (textToSend || input).trim();
    if (!query || loading) return;

    setInput("");
    const userMsg = { role: "user", content: query };
    setMessages((prev) => [...prev, userMsg]);
    setLoading(true);

    try {
      const payload = {
        message: query,
        scan_id: scanId && scanId !== "scan" && scanId !== "1" ? scanId : null,
      };
      const res = await assistantApi.chat(payload);
      if (res && res.response) {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: res.response,
            suggested_actions: res.suggested_actions || [],
            sources: res.sources || [],
          },
        ]);
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "I encountered a temporary connection issue. If you entered passwords on an unverified site, please immediately change your credentials on the official portal and enable MFA.",
          suggested_actions: ["Change password on official website", "Enable MFA"],
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed bottom-6 right-6 z-50">
      {!isOpen ? (
        <button
          onClick={() => setIsOpen(true)}
          className="flex items-center gap-2.5 px-4 py-3 rounded-2xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm shadow-xl shadow-blue-600/30 border border-blue-400/30 transition-all hover:scale-105 active:scale-95"
          aria-label="Open AI Security Assistant"
        >
          <Sparkles className="w-4 h-4 text-cyan-200 animate-pulse" />
          <span>Security Assistant</span>
          {isReportPage && (
            <span className="w-2 h-2 rounded-full bg-cyan-300 animate-ping" />
          )}
        </button>
      ) : (
        <div className="w-[380px] sm:w-[420px] h-[540px] rounded-3xl glass border border-white/10 shadow-2xl flex flex-col overflow-hidden bg-slate-950/90 backdrop-blur-xl">
          {/* Header */}
          <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between bg-white/3">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
                <Bot className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
                  TrustShield AI Assistant
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-500/10 text-cyan-300 border border-blue-500/20 font-mono">
                    SecOps
                  </span>
                </h3>
                <p className="text-[11px] text-slate-400">
                  {isReportPage ? "Context: Active Scan Report" : "Phishing & threat guidance"}
                </p>
              </div>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Messages stream */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((m, idx) => (
              <div
                key={idx}
                className={cn(
                  "flex gap-2.5",
                  m.role === "user" ? "justify-end" : "justify-start"
                )}
              >
                {m.role === "assistant" && (
                  <div className="w-6 h-6 rounded-lg bg-blue-600/20 text-blue-400 flex items-center justify-center shrink-0 mt-1">
                    <Bot className="w-3.5 h-3.5" />
                  </div>
                )}
                <div
                  className={cn(
                    "rounded-2xl p-3.5 text-xs leading-relaxed max-w-[85%]",
                    m.role === "user"
                      ? "bg-blue-600 text-white rounded-tr-sm"
                      : "bg-white/5 text-slate-200 border border-white/5 rounded-tl-sm"
                  )}
                >
                  <div className="whitespace-pre-wrap">{m.content}</div>

                  {/* Suggested action chips */}
                  {m.suggested_actions && m.suggested_actions.length > 0 && (
                    <div className="mt-3 pt-2.5 border-t border-white/5 flex flex-wrap gap-1.5">
                      {m.suggested_actions.map((act, i) => (
                        <button
                          key={i}
                          onClick={() => handleSend(act)}
                          className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 text-[10px] text-cyan-300 border border-cyan-500/20 transition-colors text-left"
                        >
                          {act}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex items-center gap-2 text-slate-400 text-xs pl-8">
                <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-400" />
                <span>Analyzing threat indicators…</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input field */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="p-3 border-t border-white/5 bg-white/3 flex gap-2"
          >
            <input
              type="text"
              placeholder="Ask security question…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="flex-1 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            <Button
              type="submit"
              size="sm"
              disabled={!input.trim() || loading}
              className="px-3"
            >
              <Send className="w-3.5 h-3.5" />
            </Button>
          </form>
        </div>
      )}
    </div>
  );
}
