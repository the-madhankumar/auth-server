# @authserver/client

The official TypeScript/JavaScript SDK for the Auth Server. Production-ready with automatic token refresh, session persistence, SSR-safety, structured error handling, and first-class React bindings.

## Features

- **Framework Agnostic** — works in vanilla JS, Vue, Svelte, Next.js, or any framework
- **React Ready** — includes `<AuthProvider>` and `useAuth()` hook
- **Auto Token Refresh** — transparently refreshes expired access tokens and retries failed requests
- **Session Persistence** — automatically saves/restores sessions via `localStorage`, `sessionStorage`, or in-memory
- **OAuth Support** — one-line Google & GitHub social login
- **MFA** — built-in support for TOTP-based multi-factor authentication
- **SSR-Safe** — defaults to `memory` storage, safe for server-side rendering
- **Structured Errors** — `AuthError` class with `code` and `status` for programmatic error handling
- **Tree-Shakeable** — `sideEffects: false` for optimal bundle size

## Installation

```bash
npm install @authserver/client
```

## Quick Start (Vanilla JS / TypeScript)

```typescript
import { AuthClient, AuthError } from '@authserver/client';

const auth = new AuthClient({
  serverUrl: 'https://auth-server-4nmm.onrender.com',
  clientId: 'your_oauth_client_id',
  storage: 'localStorage', // 'sessionStorage' | 'memory' (default)
});

// Listen to auth state changes
const unsubscribe = auth.onAuthStateChanged((session) => {
  console.log(session ? 'Logged in' : 'Logged out');
});

// Login
try {
  const session = await auth.login('user@example.com', 'password123');
  console.log('Access token:', session.access_token);
} catch (err) {
  if (err instanceof AuthError) {
    console.error(`Auth error [${err.code}]: ${err.message}`);
  }
}

// Get user profile
const user = await auth.getUser();
console.log(`Hello, ${user.first_name}!`);

// Social login (browser only — redirects the page)
auth.loginWithGoogle();
auth.loginWithGitHub();

// Cleanup
unsubscribe();
```

## Usage with React

### 1. Wrap your app with `<AuthProvider>`

```tsx
import { AuthClient } from '@authserver/client';
import { AuthProvider } from '@authserver/client/react';

const authClient = new AuthClient({
  serverUrl: 'https://auth-server-4nmm.onrender.com',
  clientId: 'your_oauth_client_id',
  storage: 'localStorage',
});

export default function App() {
  return (
    <AuthProvider client={authClient}>
      <YourApp />
    </AuthProvider>
  );
}
```

### 2. Use the `useAuth()` hook

```tsx
import { useAuth } from '@authserver/client/react';

function Dashboard() {
  const { user, isAuthenticated, isLoading, login, logout, client } = useAuth();

  if (isLoading) return <p>Loading...</p>;

  if (!isAuthenticated) {
    return (
      <div>
        <button onClick={() => login('user@example.com', 'pass')}>Login</button>
        <button onClick={() => client.loginWithGoogle()}>Login with Google</button>
      </div>
    );
  }

  return (
    <div>
      <h1>Welcome, {user?.first_name}!</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

## API Reference

### `AuthClient`

| Method | Description |
|--------|-------------|
| `login(email, password)` | Login with credentials |
| `register(email, password, firstName, lastName)` | Register a new account |
| `logout()` | Logout current session |
| `logoutAll()` | Logout from all devices |
| `refresh()` | Manually refresh the access token |
| `getUser()` | Get the authenticated user's profile |
| `updateProfile(firstName?, lastName?)` | Update profile |
| `changePassword(current, new)` | Change password |
| `deleteAccount()` | Delete the user's account |
| `loginWithGoogle()` | Redirect to Google OAuth (browser only) |
| `loginWithGitHub()` | Redirect to GitHub OAuth (browser only) |
| `verifyEmail(token)` | Verify email address |
| `resendVerification(email)` | Resend verification email |
| `forgotPassword(email)` | Send password reset email |
| `resetPassword(token, password)` | Reset password with token |
| `enableMfa()` | Enable TOTP-based MFA |
| `verifyMfa(code)` | Verify MFA setup |
| `loginMfa(email, code)` | Login with MFA code |
| `getSessions()` | List active sessions |
| `revokeSession(id)` | Revoke a specific session |
| `getAuditLogs()` | Get audit logs |
| `onAuthStateChanged(cb)` | Subscribe to auth state changes |
| `isAuthenticated()` | Check if user is logged in |
| `getAccessToken()` | Get current access token |
| `setSession(session)` | Manually set a session |

### `AuthError`

All SDK errors throw `AuthError` with:
- `message` — human-readable error
- `code` — machine-readable code (`NETWORK_ERROR`, `SESSION_EXPIRED`, `API_ERROR`, etc.)
- `status` — HTTP status code (0 for network errors)

## License
MIT
