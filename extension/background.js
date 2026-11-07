/**
 * TrustShield Browser Extension - Background Service Worker
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log("TrustShield Extension installed successfully.");
});

// Listen for tab URL updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    // Optionally pre-check domain reputation in background
  }
});

