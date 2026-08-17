import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, setToken, type User } from "./api";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .me()
      .then(({ user }) => setUser(user))
      .catch(() => setToken(null))
      .finally(() => setLoading(false));
  }, []);

  const refreshUser = () => {
    api.me().then(({ user }) => setUser(user)).catch(() => {});
  };

  const value: AuthContextValue = {
    user,
    loading,
    refreshUser,
    login: async (email, password) => {
      const { token, user } = await api.login(email, password);
      setToken(token);
      setUser(user);
    },
    signup: async (email, password) => {
      const { token, user } = await api.signup(email, password);
      setToken(token);
      setUser(user);
    },
    logout: async () => {
      try {
        await api.logout();
      } finally {
        setToken(null);
        setUser(null);
      }
    },
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
