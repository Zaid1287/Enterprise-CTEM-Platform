import { getToken } from "@/lib/auth";

/**
 * Authenticated fetch helper. Uses the same module-level token store as the
 * Orval-generated hooks (auth.ts → setAuthTokenGetter).
 * After a token refresh, getToken() always returns the current access token.
 */
export async function apiFetch<T = unknown>(path: string, options?: RequestInit): Promise<T> {
  const token = getToken();
  // Don't set Content-Type for FormData — the browser must set it with the multipart boundary
  const isFormData = options?.body instanceof FormData;
  const resp = await fetch(path, {
    ...options,
    headers: {
      ...(isFormData ? {} : { "Content-Type": "application/json" }),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options?.headers,
    },
  });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw Object.assign(new Error(body.error ?? resp.statusText), { status: resp.status });
  }
  if (resp.status === 204) return undefined as T;
  return resp.json() as T;
}
