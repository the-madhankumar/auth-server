export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  isVerified: boolean;
  role: string;
  createdAt: string;
  updatedAt: string;
  mfaEnabled: boolean;
  profileImage?: string;
}

export interface Session {
  accessToken: string;
  refreshToken?: string;
  user?: User;
}

export interface AuthClientConfig {
  /** The base URL of your auth server (e.g. https://auth.example.com) */
  serverUrl: string;
  /** Your OAuth client ID, obtained from the /oauth/clients API */
  clientId: string;
  /**
   * Where to persist the session tokens.
   * - `'localStorage'` – survives tab close (browser only)
   * - `'sessionStorage'` – cleared on tab close (browser only)
   * - `'memory'` – no persistence, lost on page reload (default, SSR-safe)
   */
  storage?: 'localStorage' | 'sessionStorage' | 'memory';
  /** Custom storage key. Defaults to `auth_session_<clientId>` */
  storageKey?: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data: T;
  error?: {
    message?: string;
    code?: string;
  };
}

export interface SessionInfo {
  id: string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

export interface AuditLog {
  id: string;
  action: string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
}

export type AuthStateChangeCallback = (session: Session | null) => void;
