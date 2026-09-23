import { createContext, useContext, useEffect, useState, useCallback } from "react";
import { api, getApiError } from "../services/api.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [initialized, setInitialized] = useState(false);

  const clear = useCallback(() => {
    setUser(null);
  }, []);

  const login = useCallback(
    async (username, password) => {
      const res = await api.post("/auth/login", { username, password });
      // The JWT is delivered only in an HttpOnly cookie; React state holds the
      // user profile and nothing is written to localStorage/sessionStorage.
      setUser(res.data.user);
      return res.data.user;
    },
    []
  );

  const register = useCallback(
    async (username, email, password) => {
      const res = await api.post("/auth/register", { username, email, password });
      setUser(res.data.user);
      return res.data.user;
    },
    []
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      // Always clear local session even if the server call fails.
    } finally {
      clear();
    }
  }, [clear]);

  useEffect(() => {
    // Session state is held only by the HttpOnly cookie, so verify it against
    // the server on every page load and collapse the session on any 401.
    const handleUnauthorized = clear;

    const bootstrapSession = () => {
      api
        .get("/auth/me")
        .then((res) => {
          setUser(res.data.user ?? res.data);
        })
        .catch(() => clear())
        .finally(() => {
          setLoading(false);
          setInitialized(true);
        });
    };

    window.addEventListener("sentinelx:unauthorized", handleUnauthorized);
    bootstrapSession();
    return () => window.removeEventListener("sentinelx:unauthorized", handleUnauthorized);
  }, [clear]);

  return (
    <AuthContext.Provider
      value={{ user, loading, initialized, login, register, logout, setUser }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export { getApiError };