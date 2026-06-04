import { AuthClientConfig, Session, User, ApiResponse, SessionInfo, AuditLog, AuthStateChangeCallback } from './types';

export class AuthError extends Error {
  public code: string;
  public status: number;

  constructor(message: string, code: string, status: number) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.status = status;
  }
}

export class AuthClient {
  private readonly serverUrl: string;
  private readonly clientId: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private readonly storageType: 'localStorage' | 'sessionStorage' | 'memory';
  private readonly storageKey: string;
  private readonly listeners: Set<AuthStateChangeCallback> = new Set();
  private isRefreshing = false;
  private refreshPromise: Promise<Session> | null = null;

  constructor(config: AuthClientConfig) {
    if (!config.serverUrl) throw new Error('serverUrl is required');
    if (!config.clientId) throw new Error('clientId is required');

    this.serverUrl = config.serverUrl.replace(/\/$/, '');
    this.clientId = config.clientId;
    this.storageType = config.storage || 'memory';
    this.storageKey = config.storageKey || `auth_session_${this.clientId}`;

    this.loadSession();
  }

  // --- Storage & Events ---

  private getStorage(): Storage | null {
    if (this.storageType === 'memory' || typeof globalThis.window === 'undefined') return null;
    return this.storageType === 'localStorage' ? globalThis.localStorage : globalThis.sessionStorage;
  }

  private loadSession() {
    const storage = this.getStorage();
    if (!storage) return;

    const stored = storage.getItem(this.storageKey);
    if (stored) {
      try {
        const session = JSON.parse(stored) as Session;
        this.accessToken = session.access_token;
        if (session.refresh_token) {
          this.refreshToken = session.refresh_token;
        }
      } catch {
        storage.removeItem(this.storageKey);
      }
    }
  }

  private saveSession(session: Session) {
    this.accessToken = session.access_token;
    if (session.refresh_token) {
      this.refreshToken = session.refresh_token;
    }

    const storage = this.getStorage();
    if (storage) {
      storage.setItem(this.storageKey, JSON.stringify({
        access_token: this.accessToken,
        refresh_token: this.refreshToken
      }));
    }

    this.notifyListeners({
      access_token: session.access_token,
      refresh_token: session.refresh_token || undefined,
      user: session.user,
    });
  }

  private clearSession() {
    this.accessToken = null;
    this.refreshToken = null;

    const storage = this.getStorage();
    if (storage) {
      storage.removeItem(this.storageKey);
    }

    this.notifyListeners(null);
  }

  /**
   * Subscribe to auth state changes. The callback fires immediately
   * with the current state, then again whenever the session changes.
   * Returns an unsubscribe function.
   */
  public onAuthStateChanged(callback: AuthStateChangeCallback): () => void {
    this.listeners.add(callback);
    // Trigger immediately with current state
    if (this.accessToken) {
      callback({ access_token: this.accessToken, refresh_token: this.refreshToken || undefined });
    } else {
      callback(null);
    }
    return () => {
      this.listeners.delete(callback);
    };
  }

  private notifyListeners(session: Session | null) {
    this.listeners.forEach(listener => {
      try {
        listener(session);
      } catch {
        // Prevent one bad listener from breaking others
      }
    });
  }

  /** Returns the current access token, or null if not authenticated */
  public getAccessToken(): string | null {
    return this.accessToken;
  }

  /** Returns the current refresh token, or null */
  public getRefreshToken(): string | null {
    return this.refreshToken;
  }

  /** Returns true if the client currently has a valid session */
  public isAuthenticated(): boolean {
    if (!this.accessToken) return false;
    return !this.isTokenExpired(this.accessToken);
  }

  private isTokenExpired(token: string): boolean {
    try {
      const payloadBase64Url = token.split('.')[1];
      if (!payloadBase64Url) return true;
      
      const payloadBase64 = payloadBase64Url.replaceAll('-', '+').replaceAll('_', '/');
      let payloadJson = '';
      
      if (typeof atob !== 'undefined') {
        payloadJson = atob(payloadBase64);
      } else if (typeof globalThis !== 'undefined' && (globalThis as any).Buffer) {
        payloadJson = (globalThis as any).Buffer.from(payloadBase64, 'base64').toString('utf8');
      } else {
        // Can't decode, fail securely by treating it as expired
        return true;
      }
      
      const decoded = JSON.parse(payloadJson);
      if (decoded.exp) {
        // exp is in seconds, add a small buffer (e.g. 5 seconds) to prevent edge cases
        return Date.now() >= (decoded.exp * 1000) - 5000;
      }
      return false;
    } catch {
      return true;
    }
  }

  /** Manually set the session (e.g. from OAuth callback URL params) */
  public setSession(session: Session) {
    this.saveSession(session);
  }

  // --- Interceptor & Fetch Logic ---

  private async fetchApi<T = any>(path: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
    const headers = new Headers(options.headers || {});

    // Only set Content-Type for requests that have a body
    if (options.body) {
      headers.set("Content-Type", "application/json");
    }

    if (this.accessToken) {
      headers.set("Authorization", `Bearer ${this.accessToken}`);
    }

    let response: Response;
    try {
      response = await fetch(`${this.serverUrl}${path}`, { ...options, headers });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new AuthError(
        `Network error: unable to reach the auth server (${msg})`,
        'NETWORK_ERROR',
        0
      );
    }

    // Handle 401 Unauthorized with auto-refresh
    if (response.status === 401 && this.refreshToken && path !== '/api/auth/refresh') {
      try {
        await this.refresh();
        // Retry the original request with the new token
        headers.set("Authorization", `Bearer ${this.accessToken}`);
        response = await fetch(`${this.serverUrl}${path}`, { ...options, headers });
      } catch {
        this.clearSession();
        throw new AuthError("Session expired. Please log in again.", 'SESSION_EXPIRED', 401);
      }
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new AuthError(
        data.error?.message || data.message || `Request failed with status ${response.status}`,
        data.error?.code || 'API_ERROR',
        response.status
      );
    }

    return data;
  }

  // --- Core Auth ---

  /** Register a new user */
  public async register(email: string, password: string, firstName: string, lastName: string): Promise<ApiResponse<User>> {
    return this.fetchApi<User>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password, first_name: firstName, last_name: lastName }),
    });
  }

  /** Login with email and password. Automatically persists the session. */
  public async login(email: string, password: string): Promise<Session> {
    const data = await this.fetchApi<Session>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    this.saveSession(data.data);
    return data.data;
  }

  /** Refresh the access token using the stored refresh token. */
  public async refresh(): Promise<Session> {
    if (!this.refreshToken) {
      throw new AuthError("No refresh token available", 'NO_REFRESH_TOKEN', 401);
    }

    // Deduplicate concurrent refresh calls
    if (this.isRefreshing && this.refreshPromise) {
      return this.refreshPromise;
    }

    this.isRefreshing = true;
    this.refreshPromise = this.fetchApi<Session>("/api/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token: this.refreshToken }),
    }).then(res => {
      this.saveSession(res.data);
      return res.data;
    }).catch(err => {
      this.clearSession();
      throw err;
    }).finally(() => {
      this.isRefreshing = false;
      this.refreshPromise = null;
    });

    return this.refreshPromise;
  }

  /** Logout the current session. Clears tokens even if the API call fails. */
  public async logout(): Promise<void> {
    try {
      if (this.refreshToken) {
        await this.fetchApi("/api/auth/logout", {
          method: "POST",
          body: JSON.stringify({ refresh_token: this.refreshToken }),
        });
      }
    } catch {
      // Best-effort server-side logout; always clear client session
    }
    this.clearSession();
  }

  /** Logout from all devices */
  public async logoutAll(): Promise<void> {
    await this.fetchApi("/api/auth/logout-all", { method: "POST" });
    this.clearSession();
  }

  // --- OAuth ---

  /**
   * Initiates Google OAuth login by redirecting the browser.
   * This method only works in browser environments.
   */
  public loginWithGoogle(): void {
    if (typeof globalThis.window === 'undefined') {
      throw new AuthError('loginWithGoogle() can only be used in a browser', 'BROWSER_ONLY', 0);
    }
    globalThis.window.location.href = `${this.serverUrl}/api/auth/google/login?client_id=${encodeURIComponent(this.clientId)}`;
  }

  /**
   * Initiates GitHub OAuth login by redirecting the browser.
   * This method only works in browser environments.
   */
  public loginWithGitHub(): void {
    if (typeof globalThis.window === 'undefined') {
      throw new AuthError('loginWithGitHub() can only be used in a browser', 'BROWSER_ONLY', 0);
    }
    globalThis.window.location.href = `${this.serverUrl}/api/auth/github/login?client_id=${encodeURIComponent(this.clientId)}`;
  }

  // --- User Profile & Account ---

  /** Get the authenticated user's profile */
  public async getUser(): Promise<User> {
    const data = await this.fetchApi<User>("/api/auth/me", { method: "GET" });
    return data.data;
  }

  /** Update the user's profile */
  public async updateProfile(firstName?: string, lastName?: string): Promise<User> {
    const data = await this.fetchApi<User>("/api/auth/profile", {
      method: "PUT",
      body: JSON.stringify({ first_name: firstName, last_name: lastName }),
    });
    return data.data;
  }

  /** Change the user's password */
  public async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.fetchApi("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
  }

  /** Delete the user's account */
  public async deleteAccount(): Promise<void> {
    await this.fetchApi("/api/auth/me", { method: "DELETE" });
    this.clearSession();
  }

  // --- Verification & Reset ---

  /** Verify email with a token */
  public async verifyEmail(token: string): Promise<void> {
    await this.fetchApi(`/api/auth/verify-email?token=${encodeURIComponent(token)}`, { method: "GET" });
  }

  /** Resend verification email */
  public async resendVerification(email: string): Promise<void> {
    await this.fetchApi("/api/auth/resend-verification", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }

  /** Send a password reset email */
  public async forgotPassword(email: string): Promise<void> {
    await this.fetchApi("/api/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }

  /** Reset password using a token */
  public async resetPassword(token: string, password: string): Promise<void> {
    await this.fetchApi("/api/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ token, password }),
    });
  }

  // --- MFA ---

  /** Enable MFA. Returns the TOTP secret and QR code data. */
  public async enableMfa(): Promise<{ secret: string; qr_code: string }> {
    const data = await this.fetchApi<{ secret: string; qr_code: string }>("/api/auth/mfa/enable", { method: "POST" });
    return data.data;
  }

  /** Verify MFA with a TOTP code (completes MFA setup) */
  public async verifyMfa(code: string): Promise<void> {
    await this.fetchApi("/api/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  /** Login with MFA code (second factor after email/password) */
  public async loginMfa(email: string, code: string): Promise<Session> {
    const data = await this.fetchApi<Session>("/api/auth/login/mfa", {
      method: "POST",
      body: JSON.stringify({ email, code }),
    });
    this.saveSession(data.data);
    return data.data;
  }

  // --- Sessions & Logs ---

  /** Get all active sessions for the user */
  public async getSessions(): Promise<SessionInfo[]> {
    const data = await this.fetchApi<SessionInfo[]>("/api/auth/sessions", { method: "GET" });
    return data.data;
  }

  /** Revoke a specific session by ID */
  public async revokeSession(sessionId: string): Promise<void> {
    await this.fetchApi(`/api/auth/sessions/${encodeURIComponent(sessionId)}`, { method: "DELETE" });
  }

  /** Get audit logs for the user */
  public async getAuditLogs(): Promise<AuditLog[]> {
    const data = await this.fetchApi<AuditLog[]>("/api/auth/audit-logs", { method: "GET" });
    return data.data;
  }
}
