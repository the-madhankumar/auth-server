import React, { createContext, useContext, useEffect, useState, useCallback, useMemo } from 'react';
import { AuthClient } from '../AuthClient';
import { Session, User } from '../types';

interface AuthContextValue {
  /** The underlying AuthClient instance */
  client: AuthClient;
  /** The current session, or null if not authenticated */
  session: Session | null;
  /** The current user profile, or null if not authenticated */
  user: User | null;
  /** Whether the user is currently authenticated */
  isAuthenticated: boolean;
  /** Whether the auth state is still being determined (initial load) */
  isLoading: boolean;
  /** Convenience: login with email/password */
  login: (email: string, password: string) => Promise<Session>;
  /** Convenience: logout */
  logout: () => Promise<void>;
  /** Convenience: refresh the user profile from the server */
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

interface AuthProviderProps {
  readonly client: AuthClient;
  readonly children: React.ReactNode;
}

export function AuthProvider({ client, children }: AuthProviderProps) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    const handleSessionChange = async (newSession: Session | null) => {
      if (!mounted) return;
      setSession(newSession);

      if (!newSession?.accessToken) {
        setUser(null);
        setIsLoading(false);
        return;
      }

      if (newSession.user) {
        setUser(newSession.user);
        setIsLoading(false);
        return;
      }

      try {
        const fetchedUser = await client.getUser();
        if (mounted) setUser(fetchedUser);
      } catch {
        // Don't wipe session — the interceptor handles 401s
      } finally {
        if (mounted) setIsLoading(false);
      }
    };

    const unsubscribe = client.onAuthStateChanged(handleSessionChange);

    return () => {
      mounted = false;
      unsubscribe();
    };
  }, [client]);

  const login = useCallback(
    async (email: string, password: string) => {
      const sess = await client.login(email, password);
      return sess;
    },
    [client]
  );

  const logout = useCallback(async () => {
    await client.logout();
  }, [client]);

  const refreshUser = useCallback(async () => {
    const u = await client.getUser();
    setUser(u);
  }, [client]);

  const value = useMemo<AuthContextValue>(
    () => ({
      client,
      session,
      user,
      isAuthenticated: !!session,
      isLoading,
      login,
      logout,
      refreshUser,
    }),
    [client, session, user, isLoading, login, logout, refreshUser]
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

/**
 * Hook to access auth state and actions.
 * Must be used inside an `<AuthProvider>`.
 */
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an <AuthProvider>');
  }
  return context;
}

/**
 * Convenience hook to access just the current user profile.
 * Re-renders only when the user profile changes.
 */
export function useUser(): User | null {
  return useAuth().user;
}

/**
 * Convenience hook to access session state.
 */
export function useSession() {
  const { session, isAuthenticated, isLoading } = useAuth();
  return { session, isAuthenticated, isLoading };
}

interface ProtectedRouteProps {
  readonly children: React.ReactNode;
  readonly fallback: React.ReactNode;
}

/**
 * A wrapper component that requires the user to be authenticated.
 * If the user is authenticated, it renders `children`.
 * If the user is not authenticated, it renders `fallback` (e.g. a login page or redirect).
 * While loading, it returns `null`.
 */
export function ProtectedRoute({ children, fallback }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) return null;
  if (!isAuthenticated) return <>{fallback}</>;

  return <>{children}</>;
}
