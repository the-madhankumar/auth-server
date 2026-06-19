import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { AuthClient, AuthError } from '../AuthClient';

const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

describe('AuthClient', () => {
  let client: AuthClient;

  beforeEach(() => {
    vi.resetAllMocks();
    // Clear storage before each test
    sessionStorage.clear();
    client = new AuthClient({
      serverUrl: 'https://auth.example.com',
      clientId: 'test-client',
      storage: 'sessionStorage'
    });
  });

  afterEach(() => {
    sessionStorage.clear();
  });

  it('initializes with no session', () => {
    expect(client.isAuthenticated()).toBe(false);
    expect(client.getAccessToken()).toBeNull();
  });

  it('handles login successfully', async () => {
    // Generate a valid, unexpired JWT mock
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const payload = btoa(JSON.stringify({ exp }));
    const validToken = `header.${payload}.signature`;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        success: true,
        data: {
          accessToken: validToken,
          refreshToken: 'mock.refresh.token',
          user: { id: '1', email: 'test@test.com' }
        }
      })
    });

    const session = await client.login('test@test.com', 'password');
    
    expect(session.accessToken).toBe(validToken);
    expect(client.isAuthenticated()).toBe(true);
    expect(client.getAccessToken()).toBe(validToken);
    
    // Verifies the session was persisted
    const stored = JSON.parse(sessionStorage.getItem('auth_session_test-client') || '{}');
    expect(stored.accessToken).toBe(validToken);
  });

  it('handles login failure and throws AuthError', async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 401,
      json: () => Promise.resolve({
        success: false,
        error: { message: 'Invalid credentials', code: 'UNAUTHORIZED' }
      })
    });

    await expect(client.login('test@test.com', 'wrong')).rejects.toThrow(AuthError);
    await expect(client.login('test@test.com', 'wrong')).rejects.toThrow('Invalid credentials');
    expect(client.isAuthenticated()).toBe(false);
  });

  it('automatically refreshes token on 401 response', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        success: true,
        data: { accessToken: 'old.expired.token', refreshToken: 'valid.refresh.token' }
      })
    });
    await client.login('test@test.com', 'password');

    // 1st request fails with 401
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      json: () => Promise.resolve({ error: { message: 'Token expired' } })
    });

    // 2nd request is the refresh call, returning new tokens
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        success: true,
        data: { accessToken: 'new.access.token', refreshToken: 'new.refresh.token' }
      })
    });

    // 3rd request is the retry of the original request
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ success: true, data: { id: '1' } })
    });

    const user = await client.getUser();
    expect(user.id).toBe('1');
    expect(client.getAccessToken()).toBe('new.access.token');
    
    // 4 fetch calls: login(success) -> getUser(fail) -> refresh(success) -> getUser(success)
    expect(mockFetch).toHaveBeenCalledTimes(4);
  });

  it('clears session on logout', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        success: true,
        data: { accessToken: 'token', refreshToken: 'refresh' }
      })
    });
    await client.login('test@test.com', 'password');
    
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ success: true })
    });

    await client.logout();
    
    expect(client.isAuthenticated()).toBe(false);
    expect(client.getAccessToken()).toBeNull();
    expect(sessionStorage.getItem('auth_session_test-client')).toBeNull();
  });

  it('triggers onAuthStateChanged listeners', async () => {
    const listener = vi.fn();
    client.onAuthStateChanged(listener);
    
    // Should fire immediately with null
    expect(listener).toHaveBeenCalledWith(null);
    
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        success: true,
        data: { accessToken: 'token' }
      })
    });
    await client.login('test@test.com', 'password');
    
    // Should fire again with the new session
    expect(listener).toHaveBeenCalledWith(expect.objectContaining({ accessToken: 'token' }));
  });

  it('triggers granular events', async () => {
    const loginListener = vi.fn();
    const logoutListener = vi.fn();
    client.on('login', loginListener);
    client.on('logout', logoutListener);

    // Generate a valid token
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const payload = btoa(JSON.stringify({ exp }));
    const validToken = `header.${payload}.signature`;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        success: true,
        data: { accessToken: validToken, refreshToken: 'mock.refresh.token' }
      })
    });

    await client.login('test@test.com', 'password');
    expect(loginListener).toHaveBeenCalledWith(expect.objectContaining({ accessToken: validToken }));

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ success: true })
    });

    await client.logout();
    expect(logoutListener).toHaveBeenCalledTimes(1);
  });
  it('disables MFA successfully', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ success: true })
    });
    await expect(client.disableMfa('password123', '123456')).resolves.toBeUndefined();
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/auth/mfa/disable'),
      expect.objectContaining({ method: 'POST' })
    );
  });
});
