# PenguWave: Security Operations Portal

A full-stack security operations portal for monitoring security events. Built with React + Vite (frontend) and Express + SQLite (backend).


## Prerequisites

- Node.js 18+

## Getting Started

### 1. Start the backend

```bash
cd backend
npm install
npm run dev
```

The backend runs at http://localhost:3001. On first start it creates a SQLite database (`backend/penguwave.db`) and seeds it with three default users:

| Email                    | Password   | Role    |
|--------------------------|------------|---------|
| admin@penguwave.io       | admin123   | admin   |
| analyst@penguwave.io     | pass456    | analyst |
| viewer@penguwave.io      | view789    | viewer  |

### 2. Start the frontend

From the project root (`part-2-secure-development`):

```bash
npm install
npm run dev
```

The frontend runs at http://localhost:5174. Open it in a browser and sign in with one of the accounts above.

## How Authentication Works

Authentication uses JSON Web Tokens (JWT) with bcrypt password hashing.

**Login flow:**

1. The user submits email and password via the login form.
2. The backend verifies the password against the bcrypt hash stored in SQLite.
3. On success, the backend returns a signed JWT containing the user's ID, email, and role. The token expires after 8 hours.
4. The frontend stores the token in `localStorage` and includes it as a `Bearer` token in the `Authorization` header on every subsequent API request.
5. The `authRequired` middleware on protected routes extracts and verifies the JWT. If the token is missing, expired, or invalid, the request is rejected with `401`.

**Session persistence:** On page reload, the frontend calls `GET /api/auth/me` with the stored token. If valid, the user remains logged in. If invalid, the token is cleared and the login screen is shown.

**Logout:** The frontend removes the token from `localStorage`. Since JWTs are stateless, no server-side session is destroyed.

## How Authorization is Enforced

Authorization uses role-based access control (RBAC) with three roles: **admin**, **analyst**, and **viewer**.

**Server-side enforcement:**

- **User management endpoints** (`GET/POST/PATCH/DELETE /api/users`) are protected by `requireRole('admin')` middleware. Non-admin users receive `403 Forbidden`.
- **Events endpoints** filter data by ownership. Admin users see all 50 events. Analyst and viewer users see only events where `event.userId` matches their own user ID. Requesting a single event that belongs to another user returns `404` (not `403`, to avoid leaking the existence of resources).
- **Passwords** are never included in any API response.

**Client-side enforcement:**

- Unauthenticated users see only the login screen - routes are not rendered.
- The "Users" navigation link and route are only rendered for admin users.
- These are UX conveniences; the backend is the actual enforcement boundary.

## Production Deployment Considerations

If deploying this system to production, I would additionally consider:

- **HTTPS.** All traffic between browser and server must be encrypted. JWT tokens in particular must never travel over plaintext HTTP.
- **Environment variables for secrets.** The JWT signing secret must come from an environment variable or secret manager, not a hardcoded default. Different secrets per environment.
- **Token storage.** Move JWT storage from `localStorage` to `httpOnly` cookies with `Secure` and `SameSite` attributes. This prevents JavaScript access to the token and mitigates XSS-based token theft.
- **Rate limiting.** Add rate limiting on the login endpoint to prevent brute-force attacks (e.g., 5 attempts per minute per IP).
- **Database.** Replace SQLite with PostgreSQL or similar for concurrent access, proper backups, and production-grade reliability.
- **Input validation.** Add stricter validation on all inputs (email format, password complexity requirements, role values).
- **Logging and monitoring.** Log authentication events, failed login attempts, and authorization failures for security monitoring and incident response.
