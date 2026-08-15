# Dashboard / Frontend Component

## Purpose

React single-page application providing the user interface for Nettle — scan results, project management, billing, and trust badge display.

## Location

- `frontend/` — All frontend code

## Technology

- React 18 + React Router 7
- Vite 8 (build tool)
- TypeScript

## Key Files

| File | Purpose |
|------|---------|
| `src/App.tsx` | Main app, routing, all page components |
| `src/AuthContext.tsx` | Authentication state (token in React context) |
| `src/api.ts` | API client (fetch wrapper with auth headers) |
| `src/main.tsx` | React DOM entry point |
| `src/styles.css` | Global styles |
| `vite.config.ts` | Vite configuration |

## Pages (defined in App.tsx)

- Login / Signup
- Dashboard (project list, scan history)
- Scan results (findings, passed checks, score)
- Billing (plan selection, checkout)
- Badge embed instructions

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `VITE_API_BASE_URL` | Backend API URL (default: `http://localhost:8080`) |

## Dependencies

- Backend API (all data comes from API calls)
- No direct database access

## Tests

None currently. Frontend changes are verified by:
- `npm run lint` (TypeScript type checking)
- `npm run build` (Vite production build)

## Common Failures

- API connection refused: Backend not running or wrong `VITE_API_BASE_URL`
- Auth token lost on refresh: Token is in React context (memory only), not persisted
- Build failures: TypeScript type errors

## How to Repair

```bash
git checkout -b fix/dashboard-<problem>
cd frontend
npm run dev    # Start dev server
# Make changes, test in browser
npm run lint   # Check types
npm run build  # Verify production build
```
