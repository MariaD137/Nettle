# Nettle (working name)

Scans AI-built apps for the security, legal, and compliance gaps their
creators don't know to look for — then keeps watching for hackers after
they ship.

## Structure

- **`backend/`** — the Tier 1 "Dry Dock" scan engine, API, and CLI. This is
  real, tested code today: hardcoded-secret detection, known-vulnerable
  dependency checks, missing privacy-policy/terms detection, undisclosed
  AI-content detection, and a missing-auth heuristic. See `backend/README.md`.
- **`infra/`** — AWS CDK app: a network-isolated VPC (no NAT, no internet
  gateway), an App Runner service for the API, and a GitHub OIDC role for
  CI/CD. Scoped to what Tier 1 actually needs, not a copy of a bigger app's
  infrastructure. See `infra/README.md`.
- **`.github/workflows/`** — CI (lint + test on every PR touching
  `backend/`) and deploy (build + push to ECR on push to `main`).

## What doesn't exist yet

- Tier 2 (continuous post-launch monitoring / hacking-attempt alerts)
- The trust badge
- A frontend/dashboard — today this is API + CLI only
- Any persistent data store, accounts, or billing

All deliberate — see `infra/README.md`'s "what's deliberately not here yet"
for the reasoning on each.
