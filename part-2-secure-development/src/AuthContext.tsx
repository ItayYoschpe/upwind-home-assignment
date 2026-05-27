import { createContext, useContext, useState, useEffect, useCallback } from "react";
import type { ReactNode } from "react";
import {
  getMe,
  logout as apiLogout,
  setUnauthorizedHandler,
  ApiError,
  BACKEND_UNAVAILABLE,
  type UserInfo,
} from "./api";

interface AuthState {
  user: UserInfo | null;
  loading: boolean;
  sessionError: string | null;
  login: (token: string, user: UserInfo) => void;
  logout: () => void;
  invalidateSession: (message: string) => void;
  clearSessionError: () => void;
}

const AuthContext = createContext<AuthState>({
  user: null,
  loading: true,
  sessionError: null,
  login: () => {},
  logout: () => {},
  invalidateSession: () => {},
  clearSessionError: () => {},
});

function sessionErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    return err.status === 0 ? BACKEND_UNAVAILABLE : err.message;
  }
  return BACKEND_UNAVAILABLE;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionError, setSessionError] = useState<string | null>(null);

  const logout = useCallback(() => {
    localStorage.removeItem("token");
    setUser(null);
    apiLogout().catch(() => {});
  }, []);

  const invalidateSession = useCallback((message: string) => {
    localStorage.removeItem("token");
    setUser(null);
    setSessionError(message);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      invalidateSession("Session expired. Please sign in again.");
    });
    return () => setUnauthorizedHandler(null);
  }, [invalidateSession]);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      setLoading(false);
      return;
    }

    getMe()
      .then((u) => {
        setUser(u);
        setSessionError(null);
      })
      .catch((err) => {
        localStorage.removeItem("token");
        setUser(null);
        setSessionError(sessionErrorMessage(err));
      })
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback((token: string, u: UserInfo) => {
    localStorage.setItem("token", token);
    setUser(u);
    setSessionError(null);
  }, []);

  const clearSessionError = useCallback(() => setSessionError(null), []);

  return (
    <AuthContext.Provider
      value={{ user, loading, sessionError, login, logout, invalidateSession, clearSessionError }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
