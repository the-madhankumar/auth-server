<a name="top"></a>

<!-- SEO: auth server, go authentication server, golang jwt oauth2, production-ready auth microservice, open source authentication, go gin postgresql, mfa totp authentication, rbac role based access control, social login google github, oauth 2.0 provider golang, typescript auth sdk, react auth provider, self-hosted auth backend, authentication api, authorization server, go microservice, secure api backend -->

<div align="center">

<br/>

<img src="./docs/assets/banner.png" alt="Auth Server — Production-Ready Authentication Microservice in Go" width="800"/>

<br/><br/>

**A complete, enterprise-grade auth backend — JWT, OAuth 2.0 Provider, MFA, RBAC, Social Login —<br/>in a single deployable Go binary.**

<br/>

[![Live API Docs](https://img.shields.io/badge/Live_API_Docs-6366F1?style=for-the-badge)](https://auth-server-4nmm.onrender.com/swagger/)
[![NPM SDK](https://img.shields.io/badge/npm-@authserver/client-CB3837?style=for-the-badge&logo=npm&logoColor=white)](https://www.npmjs.com/package/@authserver/client)
[![Release](https://img.shields.io/github/v/release/roshankumar0036singh/auth-server?style=for-the-badge&logo=github&color=181717)](https://github.com/roshankumar0036singh/auth-server/releases)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](./LICENSE)

<br/>

![Go](https://img.shields.io/badge/Go_1.25+-00ADD8?style=flat-square&logo=go&logoColor=white)
![Gin](https://img.shields.io/badge/Gin_Gonic-0081CB?style=flat-square&logo=go&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?style=flat-square&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DD0031?style=flat-square&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-0db7ed?style=flat-square&logo=docker&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=flat-square&logo=jsonwebtokens&logoColor=white)
![TypeScript](https://img.shields.io/badge/SDK-TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)

<br/>

<img src="https://img.shields.io/github/stars/roshankumar0036singh/auth-server?style=social" />
&nbsp;
<img src="https://img.shields.io/github/forks/roshankumar0036singh/auth-server?style=social" />
&nbsp;
<img src="https://img.shields.io/github/watchers/roshankumar0036singh/auth-server?style=social" />

<br/><br/>

[**Explore the API →**](https://auth-server-4nmm.onrender.com/swagger/)
&nbsp;&nbsp;·&nbsp;&nbsp;
[Report Bug](https://github.com/roshankumar0036singh/auth-server/issues)
&nbsp;&nbsp;·&nbsp;&nbsp;
[Request Feature](https://github.com/roshankumar0036singh/auth-server/discussions)
&nbsp;&nbsp;·&nbsp;&nbsp;
[Contributing](./CONTRIBUTING.md)

</div>

<br/>

---

<br/>

## 💡 Why Auth Server?

Building authentication from scratch is tedious, error-prone, and takes weeks away from your actual product. **Auth Server** gives you a battle-tested, self-hosted auth backend that deploys in under 5 minutes.

> **Ship your product, not your auth layer.**

<table>
<tr>
<td width="50%">

### For Developers
- Drop-in backend for **any** frontend stack
- Official **TypeScript SDK** with React & Next.js bindings
- Interactive **Swagger docs** — test every endpoint live
- Clean Architecture — easy to fork, extend, or contribute to
- Zero vendor lock-in — MIT licensed, self-hosted

</td>
<td width="50%">

### For Teams & Startups
- **Self-hosted** — your data never leaves your infrastructure
- Full **OAuth 2.0 Provider** — let third-party apps auth against you
- **RBAC**, audit logs, and account lockout built-in
- Docker-ready with one-command deployment
- Built-in keep-alive pinger for free-tier hosting

</td>
</tr>
</table>

<br/>

---

<br/>

## 🧬 Feature Matrix

<table>
<tr>
<th width="50%">🔐 Core Authentication</th>
<th width="50%">🛡 Security & Compliance</th>
</tr>
<tr>
<td>

&bull; JWT access & refresh token rotation<br/>
&bull; Email/password registration & login<br/>
&bull; Email verification & password reset<br/>
&bull; Social login — Google & GitHub<br/>
&bull; Multi-Factor Auth (TOTP)<br/>
&bull; Session management & multi-device logout

</td>
<td>

&bull; BCrypt password hashing<br/>
&bull; Redis-backed rate limiting<br/>
&bull; Token blacklist & revocation<br/>
&bull; CSP, CORS & security headers<br/>
&bull; Account lockout on failed attempts<br/>
&bull; Audit trail logging

</td>
</tr>
<tr>
<th>🌐 OAuth 2.0 Provider</th>
<th>🧩 Developer Experience</th>
</tr>
<tr>
<td>

&bull; Authorization Code flow (PKCE-ready)<br/>
&bull; Client registration & management<br/>
&bull; User consent screen<br/>
&bull; Per-client provider configuration<br/>
&bull; Token exchange & /userinfo endpoint<br/>
&bull; Client secret rotation & deletion

</td>
<td>

&bull; TypeScript SDK on npm<br/>
&bull; React hooks — AuthProvider + useAuth<br/>
&bull; Next.js SSR adapter<br/>
&bull; Admin SDK for user management<br/>
&bull; Interactive Swagger docs<br/>
&bull; Docker Compose one-command setup

</td>
</tr>
</table>

<br/>

### 🗺 Roadmap

| Status | Feature | Description |
|:------:|---------|-------------|
| 🔜 | **Webhooks** | Notify external systems on auth events (login, register, lock) |
| 🔜 | **SAML / SSO** | Enterprise single sign-on for corporate identity providers |
| 🔜 | **Passkeys / WebAuthn** | Passwordless authentication with biometrics |
| 🔜 | **Flutter SDK** | Mobile-first auth client for iOS & Android |
| 💭 | **Go SDK** | Server-to-server auth client for microservice architectures |
| 💭 | **Magic Links** | Passwordless email-based login flow |

> Have an idea? [Open a discussion →](https://github.com/roshankumar0036singh/auth-server/discussions)

<br/>

---

<br/>

## 🏛 Architecture

Auth Server follows **Clean Architecture** with strict separation of concerns:

```
auth-server/
├── cmd/server/main.go              # Entry point — Gin setup, GORM migration, graceful shutdown
├── internal/
│   ├── config/                     # Configuration loading, DB & Redis initialization
│   ├── routes/                     # Route definitions & middleware registration
│   ├── handler/                    # HTTP handlers — request parsing & response formatting
│   ├── service/                    # Business logic — auth flows, OAuth, MFA, email
│   ├── repository/                 # Data access layer — isolated GORM queries
│   ├── models/                     # GORM models — User, RefreshToken, OAuthClient, etc.
│   ├── middleware/                 # Auth, CORS, CSP, rate limiting, recovery
│   ├── dto/                        # Request/response data transfer objects
│   └── utils/                      # Helpers — validation, error types, JWT claims
├── clients/ts/                     # Official TypeScript SDK (published to npm)
├── templates/                      # Email templates (HTML)
├── docs/                           # Swagger UI & generated API spec
└── docker-compose.yml              # PostgreSQL + Redis orchestration
```

<br/>

---

<br/>

## 🛠 Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Language** | Go 1.25+ | High-performance compiled backend |
| **Framework** | Gin Gonic | Fast HTTP router with middleware pipeline |
| **Database** | PostgreSQL 15+ | Relational data store via GORM ORM |
| **Cache** | Redis 7+ | Rate limiting, token blacklist, sessions |
| **Auth** | JWT + OAuth 2.0 + TOTP | Industry-standard protocols |
| **Hashing** | BCrypt | Secure password storage |
| **Email** | SMTP (Gmail, SendGrid, etc.) | Transactional email delivery |
| **Docs** | Swagger / OpenAPI 3.0 | Interactive API documentation |
| **SDK** | TypeScript | React, Next.js, & Node.js bindings |
| **Deploy** | Docker & Docker Compose | Containerized deployment |

<br/>

---

<br/>

## 🚀 Quick Start

### Prerequisites

- **Go 1.25+** &nbsp;·&nbsp; **Docker & Docker Compose** &nbsp;·&nbsp; **PostgreSQL 15+** &nbsp;·&nbsp; **Redis 7+**

### Option A — Docker (Recommended)

```bash
git clone https://github.com/roshankumar0036singh/auth-server.git
cd auth-server
cp .env.example .env        # ← configure your secrets
docker compose up --build -d
```

Server runs at `http://localhost:8080` &nbsp;·&nbsp; Swagger UI at [`/swagger/`](http://localhost:8080/swagger/)

### Option B — Local Development

```bash
git clone https://github.com/roshankumar0036singh/auth-server.git
cd auth-server

# Install dependencies
go mod download

# Configure environment
cp .env.example .env

# Start PostgreSQL & Redis
docker compose up -d db redis

# Run the server
go run cmd/server/main.go
```

### Option C — Makefile

```bash
make run          # Start the server
make test         # Run all tests
make swagger      # Regenerate API docs
make build-prod   # Static production binary
```

<br/>

---

<br/>

## 📡 API Overview

> **[Full interactive docs →](https://auth-server-4nmm.onrender.com/swagger/)**

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Create a new account |
| `POST` | `/api/auth/login` | Authenticate with credentials |
| `POST` | `/api/auth/login/mfa` | Complete MFA challenge |
| `POST` | `/api/auth/refresh` | Refresh access token |
| `POST` | `/api/auth/logout` | Revoke current session |
| `POST` | `/api/auth/logout-all` | Revoke all sessions |

### User Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/auth/me` | Get current user profile |
| `PUT` | `/api/auth/profile` | Update profile |
| `POST` | `/api/auth/password` | Change password |
| `DELETE` | `/api/auth/me` | Delete account |
| `GET` | `/api/auth/sessions` | List active sessions |
| `DELETE` | `/api/auth/sessions/:id` | Revoke specific session |
| `GET` | `/api/auth/audit-logs` | View audit trail |

### Email & Verification

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/auth/verify-email` | Verify email address |
| `POST` | `/api/auth/resend-verification` | Resend verification email |
| `POST` | `/api/auth/forgot-password` | Request password reset |
| `POST` | `/api/auth/reset-password` | Reset password with token |

### MFA (Multi-Factor Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/mfa/enable` | Generate TOTP secret |
| `POST` | `/api/auth/mfa/verify` | Verify and activate MFA |
| `POST` | `/api/auth/mfa/disable` | Disable MFA |

### Social Login

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/auth/google/login` | Initiate Google OAuth |
| `GET` | `/api/auth/google/callback` | Google OAuth callback |
| `GET` | `/api/auth/github/login` | Initiate GitHub OAuth |
| `GET` | `/api/auth/github/callback` | GitHub OAuth callback |

### OAuth 2.0 Provider

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/oauth/authorize` | Authorization endpoint |
| `POST` | `/oauth/token` | Token exchange |
| `GET` | `/oauth/userinfo` | Get authorized user info |
| `POST` | `/api/auth/oauth/clients` | Register OAuth client |
| `GET` | `/api/auth/oauth/clients` | List your OAuth clients |
| `DELETE` | `/api/auth/oauth/clients/:id` | Delete OAuth client |

### Admin (Requires `admin` Role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/admin/users` | List all users (paginated) |
| `POST` | `/api/admin/users/:id/lock` | Lock user account |
| `POST` | `/api/admin/users/:id/unlock` | Unlock user account |
| `DELETE` | `/api/admin/users/:id` | Delete user account |

<br/>

---

<br/>

## 📦 TypeScript SDK

The official SDK is published on npm as [`@authserver/client`](https://www.npmjs.com/package/@authserver/client).

```bash
npm install @authserver/client
```

### Vanilla TypeScript

```typescript
import { AuthClient } from '@authserver/client';

const auth = new AuthClient({
  serverUrl: 'https://your-auth-server.com',
  clientId: 'your-client-id',
  storage: 'localStorage',
  keepAlive: true,  // prevents server sleep on free-tier hosting
});

// Register & login
await auth.register('user@example.com', 'securePassword123', 'John');
const session = await auth.login('user@example.com', 'securePassword123');

// Automatic token refresh — just call methods
const user = await auth.getUser();

// Listen for auth events
auth.on('logout', () => console.log('User signed out'));

// Cleanup when done
auth.destroy();
```

### React

```tsx
import { AuthProvider, useAuth } from '@authserver/client/react';

function App() {
  return (
    <AuthProvider serverUrl="https://your-auth-server.com" clientId="your-client-id">
      <Dashboard />
    </AuthProvider>
  );
}

function Dashboard() {
  const { user, login, logout, isAuthenticated } = useAuth();

  if (!isAuthenticated) return <button onClick={() => login('a@b.com', 'pw')}>Login</button>;
  return <p>Welcome, {user?.name}! <button onClick={logout}>Logout</button></p>;
}
```

### Next.js (SSR)

```typescript
import { createNextAuthClient } from '@authserver/client/nextjs';

export const { withAuth, getSession, handlers } = createNextAuthClient({
  serverUrl: 'https://your-auth-server.com',
  clientId: 'your-client-id',
});
```

### Admin SDK

```typescript
import { AdminClient } from '@authserver/client/admin';

const admin = new AdminClient({
  serverUrl: 'https://your-auth-server.com',
  adminToken: 'your-admin-jwt',
});

const users = await admin.listUsers();
await admin.lockUser('user-uuid');
```

> **[Full SDK documentation →](https://github.com/roshankumar0036singh/auth-server/tree/main/clients/ts)**

<br/>

---

<br/>

## ⚙ Environment Configuration

Copy `.env.example` to `.env` and configure:

| Variable | Required | Description |
|----------|:--------:|-------------|
| `APP_ENV` | Yes | `development` or `production` |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string |
| `JWT_SECRET` | Yes | Access token signing key |
| `JWT_REFRESH_SECRET` | Yes | Refresh token signing key |
| `SMTP_HOST` | Yes | Email SMTP server |
| `SMTP_USER` / `SMTP_PASSWORD` | Yes | SMTP credentials |
| `GOOGLE_CLIENT_ID` / `SECRET` | No | Google OAuth (optional) |
| `GITHUB_CLIENT_ID` / `SECRET` | No | GitHub OAuth (optional) |
| `PING_URL` | No | Self-ping URL to prevent free-tier sleep |
| `ENCRYPTION_KEY` | Yes | 32-byte key for sensitive data encryption |
| `BCRYPT_ROUNDS` | No | Password hashing cost (default: 12) |

<br/>

---

<br/>

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test ./internal/service -v

# Run a specific test
go test ./internal/service -run TestTokenService_GenerateAccessToken -v

# Generate HTML coverage report
go test ./... -coverprofile=coverage.out && go tool cover -html=coverage.out
```

<br/>

---

<br/>

## 🐳 Deployment

### Docker Compose (Full Stack)

```bash
docker compose up --build -d
```

This starts:
- **Auth Server** on port `8080`
- **PostgreSQL** on port `5432`
- **Redis** on port `6379`

### Production Build

```bash
# Static binary (no CGO dependencies)
make build-prod

# Or manually:
CGO_ENABLED=0 GOOS=linux go build -o auth-server cmd/server/main.go
```

### Cloud Deployment

| Platform | Guide |
|----------|-------|
| **Render** | Connect repo → set env vars → auto-deploy |
| **Railway** | One-click Go template → configure `.env` |
| **Fly.io** | `fly launch` → `fly deploy` |
| **AWS / GCP / Azure** | Docker image or binary deployment |

> **Tip**: Set `PING_URL` to your public URL's `/health` endpoint to prevent free-tier platforms from putting your server to sleep. Auth Server includes a built-in self-pinger that hits this URL every 14 minutes.

<br/>

---

<br/>

## 🤝 Contributing

We welcome contributions of all sizes — from typo fixes to new features.

```bash
# Fork → Clone → Branch
git checkout -b feature/your-feature

# Make changes → Test
go test ./...

# Commit (we use Conventional Commits)
git commit -m "feat: add amazing feature"

# Push → Open PR
git push origin feature/your-feature
```

> Read the full **[Contributing Guide →](./CONTRIBUTING.md)** &nbsp;·&nbsp; **[Code of Conduct →](./CODE_OF_CONDUCT.md)**

### Ways to Contribute

- **Bug reports** — [Open an issue](https://github.com/roshankumar0036singh/auth-server/issues)
- **Feature requests** — [Start a discussion](https://github.com/roshankumar0036singh/auth-server/discussions)
- **Documentation** — Improve guides, add examples
- **Tests** — Increase coverage, add edge cases
- **Integrations** — Build SDKs for other languages

<br/>

---

<br/>

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](./LICENSE) for details.

<br/>

## Author

**Roshan Kumar Singh**

[![GitHub](https://img.shields.io/badge/@roshankumar0036singh-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/roshankumar0036singh)

---

<div align="center">

**If Auth Server helped you, consider giving it a ⭐**

<br/>

<a href="#top"><img src="https://img.shields.io/badge/Back_to_Top-6366F1?style=for-the-badge" /></a>

</div>
