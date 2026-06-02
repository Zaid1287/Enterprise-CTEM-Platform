import { setAuthTokenGetter } from "@workspace/api-client-react";

let _token: string | null = null;
let _onTokenExpired: (() => void) | null = null;
let _isRefreshing = false;
let _refreshQueue: Array<(success: boolean) => void> = [];

export function getToken(): string | null {
  return _token;
}

export function setToken(token: string | null): void {
  _token = token;
  setAuthTokenGetter(token ? () => token : null);
}

export function onTokenExpired(handler: () => void): void {
  _onTokenExpired = handler;
}

export function handleTokenExpired(): void {
  _token = null;
  setAuthTokenGetter(null);
  _onTokenExpired?.();
}

// Restore token from session storage on page load
const stored = sessionStorage.getItem("ctem_token");
if (stored) {
  setToken(stored);
}

export function persistToken(token: string | null): void {
  setToken(token);
  if (token) {
    sessionStorage.setItem("ctem_token", token);
  } else {
    sessionStorage.removeItem("ctem_token");
    sessionStorage.removeItem("ctem_user");
  }
}

export async function attemptTokenRefresh(): Promise<boolean> {
  const refreshToken = sessionStorage.getItem("ctem_refresh_token");
  if (!refreshToken) return false;

  if (_isRefreshing) {
    return new Promise((resolve) => {
      _refreshQueue.push(resolve);
    });
  }

  _isRefreshing = true;
  try {
    const res = await fetch("/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });

    if (!res.ok) {
      _refreshQueue.forEach((cb) => cb(false));
      _refreshQueue = [];
      return false;
    }

    const data = await res.json();
    persistToken(data.accessToken);
    sessionStorage.setItem("ctem_refresh_token", data.refreshToken);
    sessionStorage.setItem("ctem_user", JSON.stringify(data.user));

    _refreshQueue.forEach((cb) => cb(true));
    _refreshQueue = [];
    return true;
  } catch {
    _refreshQueue.forEach((cb) => cb(false));
    _refreshQueue = [];
    return false;
  } finally {
    _isRefreshing = false;
  }
}
