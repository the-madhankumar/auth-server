export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  is_verified: boolean;
  role: string;
  created_at: string;
  updated_at: string;
  mfa_enabled: boolean;
  profile_image?: string;
}

export interface Session {
  access_token: string;
  refresh_token?: string;
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
  ip_address: string;
  user_agent: string;
  created_at: string;
  expires_at: string;
  is_current: boolean;
}

export interface AuditLog {
  id: string;
  action: string;
  ip_address: string;
  user_agent: string;
  created_at: string;
}

export type AuthStateChangeCallback = (session: Session | null) => void;
