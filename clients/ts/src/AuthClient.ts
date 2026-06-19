import { AuthClientConfig, Session, User, ApiResponse, SessionInfo, AuditLog, AuthStateChangeCallback, AuthEvents } from './types';

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
  private readonly listeners: Map<keyof AuthEvents, Set<any>> = new Map();
  private isRefreshing = false;
  private refreshPromise: Promise<Session> | null = null;
  private refreshTimeout: ReturnType<typeof setTimeout> | null = null;
  private keepAliveIntervalId: ReturnType<typeof setInterval> | null = null;
  private readonly retries: number;
  private readonly retryDelay: number;

  constructor(config: AuthClientConfig) {
    if (!config.serverUrl) throw new Error('serverUrl is required');
    if (!config.clientId) throw new Error('clientId is required');

    this.serverUrl = config.serverUrl.replace(/\/$/, '');
    this.clientId = config.clientId;
    this.storageType = config.storage || 'memory';
    this.storageKey = config.storageKey || `auth_session_${this.clientId}`;
    this.retries = config.retries ?? 0;
    this.retryDelay = config.retryDelay ?? 1000;

    if (config.keepAlive && globalThis.setInterval !== undefined) {
      const interval = config.keepAliveInterval ?? 300000; // 5 minutes
      this.keepAliveIntervalId = setInterval(() => {
        fetch(`${this.serverUrl}/health`).catch(() => {});
      }, interval);
    }

    this.loadSession();
  }

  /**
   * Cleans up the auth client by clearing timers. 
   * Should be called when the client is no longer needed to prevent memory leaks.
   */
  public destroy(): void {
    if (this.keepAliveIntervalId) {
      clearInterval(this.keepAliveIntervalId);
      this.keepAliveIntervalId = null;
    }
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
      this.refreshTimeout = null;
    }
  }

  // --- Storage & Events ---

  private getStorage(): Storage | null {
    if (this.storageType === 'memory' || globalThis.window === undefined) return null;
    return this.storageType === 'localStorage' ? globalThis.localStorage : globalThis.sessionStorage;
  }

  private loadSession() {
    const storage = this.getStorage();
    if (!storage) return;

    const stored = storage.getItem(this.storageKey);
    if (stored) {
      try {
        const session = JSON.parse(stored) as Session;
        this.accessToken = session.accessToken;
        if (session.refreshToken) {
          this.refreshToken = session.refreshToken;
        }
      } catch {
        storage.removeItem(this.storageKey);
      }
    }
  }

  private saveSession(session: Session) {
    this.accessToken = session.accessToken;
    this.refreshToken = session.refreshToken ?? null;

    const storage = this.getStorage();
    if (storage) {
      storage.setItem(this.storageKey, JSON.stringify({
        accessToken: this.accessToken,
        refreshToken: this.refreshToken
      }));
    }

    this.scheduleTokenRefresh(session.accessToken);

    this.emit('session', {
      accessToken: session.accessToken,
      refreshToken: session.refreshToken || undefined,
      user: session.user,
    });
  }

  private clearSession() {
    this.accessToken = null;
    this.refreshToken = null;
    
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
      this.refreshTimeout = null;
    }

    const storage = this.getStorage();
    if (storage) {
      storage.removeItem(this.storageKey);
    }

    this.emit('session', null);
  }

  private scheduleTokenRefresh(token: string) {
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
      this.refreshTimeout = null;
    }

    if (globalThis.setTimeout === undefined) return;

    try {
      const payloadBase64Url = token.split('.')[1];
      if (!payloadBase64Url) return;
      const payloadBase64 = payloadBase64Url.replaceAll('-', '+').replaceAll('_', '/');
      const payloadJson = typeof atob === 'undefined' ? (globalThis as any).Buffer.from(payloadBase64, 'base64').toString('utf8') : atob(payloadBase64);
      const decoded = JSON.parse(payloadJson);
      
      if (decoded.exp) {
        // Refresh 30 seconds before expiration
        const timeToRefresh = (decoded.exp * 1000) - Date.now() - 30000;
        if (timeToRefresh > 0) {
          this.refreshTimeout = setTimeout(() => {
            this.refresh().catch(() => {});
          }, timeToRefresh);
        } else {
          // If already expired or within 30s, refresh immediately
          this.refresh().catch(() => {});
        }
      }
    } catch {
      // Ignore parsing errors
    }
  }

  /**
   * Subscribe to fine-grained auth events.
   * Returns an unsubscribe function.
   */
  public on<K extends keyof AuthEvents>(event: K, listener: AuthEvents[K]): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(listener);

    // Legacy support: if listening to session and there's a token, fire immediately
    if (event === 'session') {
      const legacyListener = listener as AuthEvents['session'];
      if (this.accessToken) {
        legacyListener({ accessToken: this.accessToken, refreshToken: this.refreshToken || undefined });
      } else {
        legacyListener(null);
      }
    }

    return () => {
      this.listeners.get(event)?.delete(listener);
    };
  }

  /**
   * Legacy method to subscribe to auth state changes.
   * Alias for `on('session', callback)`.
   */
  public onAuthStateChanged(callback: AuthStateChangeCallback): () => void {
    return this.on('session', callback);
  }

  private emit<K extends keyof AuthEvents>(event: K, ...args: Parameters<AuthEvents[K]>): void {
    const handlers = this.listeners.get(event) as Set<AuthEvents[K]> | undefined;
    if (handlers) {
      handlers.forEach(handler => {
        try {
          (handler as (...a: Parameters<AuthEvents[K]>) => void)(...args);
        } catch {
          // Prevent one bad listener from breaking others
        }
      });
    }
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
      
      if (typeof atob === 'undefined') {
        if (typeof globalThis !== 'undefined' && (globalThis as any).Buffer) {
          payloadJson = (globalThis as any).Buffer.from(payloadBase64, 'base64').toString('utf8');
        } else {
          // Can't decode, fail securely by treating it as expired
          return true;
        }
      } else {
        payloadJson = atob(payloadBase64);
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



  // --- Interceptor & Fetch Logic ---

  private async fetchApi<T = any>(path: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
    const headers = new Headers(options.headers || {});

    // Only set Content-Type for requests that have a body
    if (options.body) {
      headers.set("Content-Type", "application/json");
    }

    const response = await this.executeWithRetry(path, options, headers);

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const authErr = new AuthError(
        data.error?.message || data.message || `Request failed with status ${response.status}`,
        data.error?.code || 'API_ERROR',
        response.status
      );
      this.emit('error', authErr);
      throw authErr;
    }

    return data;
  }

  private async executeWithRetry(path: string, options: RequestInit, headers: Headers): Promise<Response> {
    let attempt = 0;
    const maxAttempts = this.retries + 1;

    while (attempt < maxAttempts) {
      attempt++;
      
      if (this.accessToken) {
        headers.set("Authorization", `Bearer ${this.accessToken}`);
      }

      try {
        const response = await fetch(`${this.serverUrl}${path}`, { ...options, headers });
        
        // Break out of retry loop for successful or 4xx responses (except 401 which we handle below)
        if (response.ok || (response.status >= 400 && response.status < 500 && response.status !== 401)) {
          return response;
        }

        // Handle 401 Unauthorized with auto-refresh
        if (response.status === 401 && this.refreshToken && path !== '/api/auth/refresh') {
          return await this.handleUnauthorizedRetry(path, options, headers);
        }

        if (attempt >= maxAttempts) {
          if (response.status >= 500) {
            throw new AuthError(
              `Request failed after ${this.retries + 1} attempts with status ${response.status}`,
              'MAX_RETRIES_EXCEEDED',
              response.status
            );
          }
          return response;
        }
      } catch (err: unknown) {
        if (attempt >= maxAttempts) {
          const msg = err instanceof Error ? err.message : String(err);
          const authErr = new AuthError(`Network error: unable to reach the auth server (${msg})`, 'NETWORK_ERROR', 0);
          this.emit('error', authErr);
          throw authErr;
        }
      }

      // Exponential backoff
      const delay = this.retryDelay * Math.pow(2, attempt - 1);
      await new Promise(r => setTimeout(r, delay));
    }
    throw new AuthError("Network error: request failed", 'NETWORK_ERROR', 0);
  }

  private async handleUnauthorizedRetry(path: string, options: RequestInit, headers: Headers): Promise<Response> {
    try {
      await this.refresh();
      // Retry the original request immediately without backoff delay
      headers.set("Authorization", `Bearer ${this.accessToken!}`);
      return await fetch(`${this.serverUrl}${path}`, { ...options, headers });
    } catch {
      this.clearSession();
      throw new AuthError("Session expired. Please log in again.", 'SESSION_EXPIRED', 401);
    }
  }

  // --- Core Auth ---

  /** 
   * Register a new user. 
   * @param email User's email address
   * @param password Must be at least 8 characters
   * @param firstName User's first name
   * @param lastName User's last name
   * @returns An ApiResponse containing the registered User profile
   */
  public async register(email: string, password: string, firstName: string, lastName: string): Promise<ApiResponse<User>> {
    return this.fetchApi<User>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password, firstName, lastName }),
    });
  }

  /** 
   * Login with email and password. Automatically persists the session tokens.
   * If MFA is required, the returned Session will have `mfaRequired: true` and an `mfaToken`.
   * @param email User's email address
   * @param password User's password
   * @returns The session containing the access/refresh tokens and user profile
   */
  public async login(email: string, password: string): Promise<Session> {
    const data = await this.fetchApi<Session>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    this.saveSession(data.data);
    this.emit('login', data.data);
    return data.data;
  }

  /** 
   * Refresh the access token using the stored refresh token. 
   * Calling this concurrently from multiple places will deduplicate into a single network request.
   * @returns The newly refreshed session
   * @throws {AuthError} if no refresh token is available or if the refresh fails
   */
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
      body: JSON.stringify({ refreshToken: this.refreshToken }),
    }).then(res => {
      this.saveSession(res.data);
      this.emit('token:refreshed', res.data);
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
          body: JSON.stringify({ refreshToken: this.refreshToken }),
        });
      }
    } catch {
      // Best-effort server-side logout; always clear client session
    }
    this.clearSession();
    this.emit('logout');
  }

  /** Logout from all devices */
  public async logoutAll(): Promise<void> {
    await this.fetchApi("/api/auth/logout-all", { method: "POST" });
    this.clearSession();
    this.emit('logout');
  }

  // --- OAuth ---

  /**
   * Initiates Google OAuth login by redirecting the browser.
   * This method only works in browser environments.
   *
   * @param redirectUri Where the auth server sends the browser back to after
   *   login (must be registered on your OAuth client). The callback receives
   *   `access_token`/`refresh_token` query params — call
   *   {@link AuthClient.completeOAuthRedirect} there. When omitted, the server
   *   returns the session as JSON (legacy behavior).
   */
  public loginWithGoogle(redirectUri?: string): void {
    this.redirectToSocialLogin('google', redirectUri);
  }

  /**
   * Initiates GitHub OAuth login by redirecting the browser.
   * This method only works in browser environments.
   *
   * @param redirectUri See {@link AuthClient.loginWithGoogle}.
   */
  public loginWithGitHub(redirectUri?: string): void {
    this.redirectToSocialLogin('github', redirectUri);
  }

  private redirectToSocialLogin(provider: 'google' | 'github', redirectUri?: string): void {
    if (globalThis.window === undefined) {
      throw new AuthError(`loginWith${provider === 'google' ? 'Google' : 'GitHub'}() can only be used in a browser`, 'BROWSER_ONLY', 0);
    }
    let url = `${this.serverUrl}/api/auth/${provider}/login?client_id=${encodeURIComponent(this.clientId)}`;
    if (redirectUri) {
      url += `&redirect_uri=${encodeURIComponent(redirectUri)}`;
    }
    globalThis.window.location.href = url;
  }

  /**
   * Completes a social-login redirect in the browser. Reads `access_token` and
   * `refresh_token` from the current URL's query string (set by the auth server
   * after Google/GitHub login), stores the session, and strips the tokens from
   * the visible URL. Returns the session, or `null` when no tokens are present.
   *
   * @param href Optional URL to parse instead of `window.location.href`.
   */
  public completeOAuthRedirect(href?: string): Session | null {
    const source = href ?? (globalThis.window === undefined ? undefined : globalThis.window.location.href);
    if (!source) return null;

    let parsed: URL;
    try {
      parsed = new URL(source);
    } catch {
      return null;
    }
    const accessToken = parsed.searchParams.get('access_token');
    if (!accessToken) return null;

    const refreshToken = parsed.searchParams.get('refresh_token') ?? undefined;
    const session: Session = { accessToken, refreshToken };
    this.saveSession(session);

    if (!href && globalThis.window !== undefined) {
      parsed.searchParams.delete('access_token');
      parsed.searchParams.delete('refresh_token');
      globalThis.window.history.replaceState({}, '', parsed.pathname + parsed.search + parsed.hash);
    }

    return session;
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
      body: JSON.stringify({ firstName, lastName }),
    });
    return data.data;
  }

  /** Change the user's password */
  public async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.fetchApi("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword }),
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

  /** 
   * Enable MFA. 
   * @returns The TOTP secret and a qrCodeUrl (otpauth:// URI) to scan in Google Authenticator or Authy.
   */
  public async enableMfa(): Promise<{ secret: string; qrCodeUrl: string }> {
    const data = await this.fetchApi<{ secret: string; qrCodeUrl: string }>("/api/auth/mfa/enable", { method: "POST" });
    return data.data;
  }

  /** Verify MFA with a TOTP code (completes MFA setup) */
  public async verifyMfa(code: string): Promise<void> {
    await this.fetchApi("/api/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  /** 
   * Disable MFA. Requires re-authenticating with the user's password and a current TOTP code. 
   * @param password The user's current password
   * @param code The current 6-digit TOTP code
   */
  public async disableMfa(password: string, code: string): Promise<void> {
    await this.fetchApi("/api/auth/mfa/disable", {
      method: "POST",
      body: JSON.stringify({ password, code }),
    });
  }

  /** 
   * Login with MFA code (second factor after email/password).
   * @param mfaToken The short-lived mfaToken returned by the initial `login()` call when mfaRequired is true.
   * @param code The 6-digit TOTP code from the user's authenticator app.
   */
  public async loginMfa(mfaToken: string, code: string): Promise<Session> {
    const data = await this.fetchApi<Session>("/api/auth/login/mfa", {
      method: "POST",
      body: JSON.stringify({ mfaToken, code }),
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
