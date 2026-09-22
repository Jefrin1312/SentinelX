import { createContext, useContext, useEffect, useState, useCallback } from "react";
import { api, getApiError } from "../services/api.js";

const AuthContext = createContext(null);

function readUser() {
  try {
    return JSON.parse(localStorage.getItem("sentinelx_user") || "null");
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(readUser);
  const [loading, setLoading] = useState(true);
  const [initialized, setInitialized] = useState(false);

  const persist = useCallback((token, userData) => {
    localStorage.setItem("sentinelx_token", token);
    localStorage.setItem("sentinelx_user", JSON.stringify(userData));
    setUser(userData);
  }, []);

  const clear = useCallback(() => {
    localStorage.removeItem("sentinelx_token");
    localStorage.removeItem("sentinelx_user");
    setUser(null);
  }, []);

  const login = useCallback(
    async (username, password) => {
      const res = await api.post("/auth/login", { username, password });
      persist(res.data.access_token, res.data.user);
      return res.data.user;
    },
    [persist]
  );

  const register = useCallback(
    async (username, email, password) => {
      const res = await api.post("/auth/register", { username, email, password });
      persist(res.data.access_token, res.data.user);
      return res.data.user;
    },
    [persist]
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
    const token = localStorage.getItem("sentinelx_token");
    if (!token) {
      setLoading(false);
      setInitialized(true);
      return;
    }
    api
      .get("/auth/me")
      .then((res) => {
        localStorage.setItem("sentinelx_user", JSON.stringify(res.data));
        setUser(res.data);
      })
      .catch(() => clear())
      .finally(() => {
        setLoading(false);
        setInitialized(true);
      });
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