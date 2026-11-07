/**
 * TrustShield Centralized API Client
 * Manages baseURL, automatic Authorization Bearer injection,
 * and seamless 401 token refreshing.
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || "";

let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

export async function apiFetch(endpoint, options = {}) {
  const url = endpoint.startsWith("http") ? endpoint : `${API_BASE_URL}${endpoint}`;

  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  const token = localStorage.getItem("ts_token");
  if (token && !headers["Authorization"]) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const config = {
    ...options,
    headers,
    credentials: "include", // Send & receive HttpOnly cookies
  };

  let response;
  try {
    response = await fetch(url, config);
  } catch (netErr) {
    // If proxy failed, attempt direct connection to backend port 8000
    if (!url.startsWith("http://127.0.0.1:8000") && !url.startsWith("http://localhost:8000")) {
      try {
        const directUrl = `http://127.0.0.1:8000${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;
        response = await fetch(directUrl, config);
      } catch (directErr) {
        throw new Error(directErr.message || "Network error. Please check backend connection.");
      }
    } else {
      throw new Error(netErr.message || "Network error. Please check backend connection.");
    }
  }

  // Handle 401 Unauthorized for token refresh (except for login/register itself)
  if (response.status === 401 && !endpoint.includes("/auth/login") && !endpoint.includes("/auth/register") && !endpoint.includes("/auth/refresh")) {
    const refreshToken = localStorage.getItem("ts_refresh_token");

    if (!refreshToken) {
      localStorage.removeItem("ts_token");
      localStorage.removeItem("ts_refresh_token");
      localStorage.setItem("ts_logged_out", "true");
      window.dispatchEvent(new Event("ts_auth_logout"));
      const err = await parseError(response);
      throw err;
    }

    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject });
      }).then((newToken) => {
        headers["Authorization"] = `Bearer ${newToken}`;
        return fetch(url, { ...config, headers });
      });
    }

    isRefreshing = true;

    try {
      const refreshRes = await fetch(`${API_BASE_URL}/api/v1/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (!refreshRes.ok) {
        throw new Error("Refresh token expired");
      }

      const refreshData = await refreshRes.json();
      localStorage.setItem("ts_token", refreshData.access_token);
      localStorage.setItem("ts_refresh_token", refreshData.refresh_token);
      headers["Authorization"] = `Bearer ${refreshData.access_token}`;

      processQueue(null, refreshData.access_token);
      isRefreshing = false;

      // Retry original request
      return fetch(url, { ...config, headers });
    } catch (refreshErr) {
      processQueue(refreshErr, null);
      isRefreshing = false;
      localStorage.removeItem("ts_token");
      localStorage.removeItem("ts_refresh_token");
      localStorage.setItem("ts_logged_out", "true");
      window.dispatchEvent(new Event("ts_auth_logout"));
      throw refreshErr;
    }
  }

  if (!response.ok) {
    const err = await parseError(response);
    throw err;
  }

  return response.json();
}

async function parseError(response) {
  try {
    const data = await response.json();
    if (data.error && data.error.message) {
      const error = new Error(data.error.message);
      error.code = data.error.code;
      error.details = data.error.details;
      error.status = response.status;
      return error;
    }
    if (data.detail) {
      const error = new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail));
      error.status = response.status;
      return error;
    }
  } catch (_) {
    // Non-JSON error
  }
  const error = new Error(`Request failed with status ${response.status}`);
  error.status = response.status;
  return error;
}

export const authApi = {
  register: (payload) =>
    apiFetch("/api/v1/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  login: (payload) =>
    apiFetch("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getMe: () =>
    apiFetch("/api/v1/auth/me", {
      method: "GET",
    }),

  refresh: (refreshToken) =>
    apiFetch("/api/v1/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token: refreshToken }),
    }),

  logout: () =>
    apiFetch("/api/v1/auth/logout", {
      method: "POST",
    }),

  getOAuthStatus: () =>
    apiFetch("/api/v1/auth/oauth/status", {
      method: "GET",
    }),

  configureOAuth: (payload) =>
    apiFetch("/api/v1/auth/oauth/configure", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
};

