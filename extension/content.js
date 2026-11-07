/**
 * TrustShield Browser Extension - Content Script
 * Passive warning banner for dangerous domains.
 */

(function () {
  const currentHost = window.location.hostname.toLowerCase();

  // If local or standard search engines, skip
  if (
    currentHost === "localhost" ||
    currentHost === "127.0.0.1" ||
    currentHost.endsWith(".google.com") ||
    currentHost.endsWith(".github.com")
  ) {
    return;
  }

  // Check if domain is known dangerous (e.g. from local storage cache)
  try {
    chrome.storage.local.get(["blocked_domains"], (res) => {
      const blocked = res.blocked_domains || [];
      if (blocked.includes(currentHost)) {
        renderWarningBanner();
      }
    });
  } catch (_) {}

  function renderWarningBanner() {
    if (document.getElementById("trustshield-warning-banner")) return;

    const banner = document.createElement("div");
    banner.id = "trustshield-warning-banner";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483647;
      background: #7f1d1d;
      color: #ffffff;
      padding: 10px 16px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
      border-bottom: 2px solid #ef4444;
    `;

    banner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-size: 16px;">⚠️</span>
        <span><strong>TrustShield Warning:</strong> This website was flagged as potentially deceptive or phishing. Do not submit passwords or sensitive data.</span>
      </div>
      <div style="display: flex; gap: 8px;">
        <button id="ts-dismiss" style="background: rgba(255,255,255,0.2); border: none; color: white; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px;">Dismiss</button>
      </div>
    `;

    document.body.prepend(banner);

    document.getElementById("ts-dismiss")?.addEventListener("click", () => {
      banner.remove();
    });
  }
})();

