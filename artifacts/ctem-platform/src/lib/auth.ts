import { setAuthTokenGetter } from "@workspace/api-client-react";

let _token: string | null = null;
let _onTokenExpired: (() => void) | null = null;

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
