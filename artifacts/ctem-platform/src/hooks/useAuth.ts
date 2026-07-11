import { create } from "zustand";
import { persistToken, getToken } from "@/lib/auth";

export interface AuthUser {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  tenantId: number;
}

interface AuthStore {
  user: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;
  aiMapperEnabled: boolean;
  aiMapperLoaded: boolean;
  tprmEnabled: boolean;
  tprmLoaded: boolean;
  login: (token: string, refreshToken: string, user: AuthUser) => void;
  logout: () => void;
  setUser: (user: AuthUser) => void;
  setAiMapperEnabled: (enabled: boolean) => void;
  setTprmEnabled: (enabled: boolean) => void;
}

function getStoredUser(): AuthUser | null {
  try {
    const raw = sessionStorage.getItem("ctem_user");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export const useAuth = create<AuthStore>((set) => ({
  user: getStoredUser(),
  token: getToken(),
  isAuthenticated: !!getToken(),
  aiMapperEnabled: false,
  aiMapperLoaded: false,
  tprmEnabled: false,
  tprmLoaded: false,

  login: (token, refreshToken, user) => {
    persistToken(token);
    sessionStorage.setItem("ctem_user", JSON.stringify(user));
    sessionStorage.setItem("ctem_refresh_token", refreshToken);
    set({ user, token, isAuthenticated: true });
  },

  logout: () => {
    persistToken(null);
    sessionStorage.removeItem("ctem_user");
    sessionStorage.removeItem("ctem_refresh_token");
    set({ user: null, token: null, isAuthenticated: false, aiMapperEnabled: false, aiMapperLoaded: false, tprmEnabled: false, tprmLoaded: false });
  },

  setUser: (user) => {
    sessionStorage.setItem("ctem_user", JSON.stringify(user));
    set({ user });
  },

  setAiMapperEnabled: (enabled: boolean) => set({ aiMapperEnabled: enabled, aiMapperLoaded: true }),
  setTprmEnabled: (enabled: boolean) => set({ tprmEnabled: enabled, tprmLoaded: true }),
}));
