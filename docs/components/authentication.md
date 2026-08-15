# Authentication Component

## Purpose

Handles user registration, login, logout, password reset, and session management.

## Location

- `backend/src/auth/` — Core auth logic
- `backend/src/routes/auth.routes.ts` — HTTP endpoints
- `frontend/src/AuthContext.tsx` — Client-side auth state

## Files

| File | Purpose |
|------|---------|
| `auth/users.ts` | User creation, lookup by email/id |
| `auth/passwords.ts` | Scrypt password hashing and verification |
| `auth/sessions.ts` | Session token creation, validation, deletion |
| `auth/middleware.ts` | `requireAuth` Express middleware |
| `routes/auth.routes.ts` | `/api/auth/*` endpoints |

## API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/auth/signup` | No | Create account |
| POST | `/api/auth/login` | No | Login, receive session token |
| POST | `/api/auth/logout` | Yes | Invalidate session token |
| GET | `/api/auth/me` | Yes | Get current user |
| POST | `/api/auth/forgot-password` | No | Request password reset |
| POST | `/api/auth/reset-password` | No | Reset password with token |

## Database Tables

- `users` — `id`, `email`, `password_hash`, `plan`, `stripe_customer_id`, `subscription_status`, `created_at`
- `sessions` — `token`, `user_id`, `created_at`, `expires_at`
- `password_resets` — `token`, `user_id`, `expires_at`

## Dependencies

- `backend/src/db/index.ts` — Database connection
- Node.js `crypto` module — Password hashing (scrypt), token generation

## External Services

None. Auth is fully self-contained.

## Tests

- `backend/test/auth.test.ts` — Password hashing, user creation, HTTP flow (signup/login/logout), input validation

## Common Failures

- "UNIQUE constraint failed: users.email" — duplicate signup attempt
- Session token expired — check `sessions.ts` expiry duration
- Missing Authorization header — frontend not sending Bearer token

## How to Repair

```bash
git checkout -b fix/auth-<problem>
# Edit files in backend/src/auth/ or backend/src/routes/auth.routes.ts
NETTLE_DB_PATH=:memory: node --import tsx --test test/auth.test.ts
```

## Rollback

Auth changes are code-only (no schema migrations). Revert the commit to roll back.
