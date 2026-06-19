# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.5] - Unreleased

### Added
- `VERSION` export for the current SDK version.
- `AdminClient` class to perform administrative actions (`listUsers`, `lockUser`, `unlockUser`, `deleteUser`). Exported via `@authserver/client/admin`.
- Proactive Token Refresh: Tokens automatically refresh 30 seconds before expiration.
- Fine-grained Event Emitter: `on()` method added with specific events (`session`, `login`, `logout`, `token:refreshed`, `error`).
- Fetch Retry with Exponential Backoff: `retries` and `retryDelay` settings added to `AuthClientConfig` to automatically retry network failures.
- Server Keep-Alive Ping: `keepAlive` and `keepAliveInterval` settings added to `AuthClientConfig` to optionally ping the server's health endpoint to prevent sleep.
- `disableMfa(password, code)` method to disable TOTP multi-factor authentication.
- React hooks: `useUser()` and `useSession()`.
- React component: `<ProtectedRoute>`.
- JSDoc annotations for core methods.
- Comprehensive `vitest` unit test suite.

### Breaking Changes
- `loginMfa(email, code)` signature changed to `loginMfa(mfaToken, code)`. 
  Replace the first argument with the `mfaToken` returned by `login()` when `mfaRequired: true`.

### Fixed
- Fixed a bug where a missing `refreshToken` would persist the previous session's refresh token due to `undefined` handling.

## [1.0.4] - 2026-06-18

### Fixed
- Support for backward compatibility and deduplication of token logic.
- Next.js cookie handling improvements.

## [1.0.0] - 2026-06-15

### Added
- Initial release.
- Core authentication features: register, login, logout, refresh.
- Social login (Google, GitHub).
- Next.js adapter with HTTP-only cookie proxy.
- React bindings (`AuthProvider`, `useAuth`).
- MFA support.
