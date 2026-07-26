# Nettle — backend

Tier 1 "Dry Dock" scan engine and API. Scans an AI-built app's codebase for
launch-readiness gaps: hardcoded secrets, known-vulnerable dependencies,
missing privacy policy / terms of service, undisclosed AI-generated content,
and routes with no visible authentication check.

This isn't a mockup — the scan engine is real static analysis, covered by
tests that assert on actual findings against two fixture apps: one seeded
with real issues (`test/fixtures/sample-app`) and one clean
(`test/fixtures/clean-app`).

## Use it

```bash
npm install
npm run build

# CLI
node bin/nettle.js scan /path/to/some/app

# API
npm start                 # listens on :8080
curl -X POST http://localhost:8080/api/scans \
  -F "codebase=@/path/to/app.zip"
```

## Develop

```bash
npm run dev     # tsx watch, hot reload
npm test        # real assertions against the fixture apps
npm run lint    # tsc --noEmit
```

## What's actually checked today

| Check | How |
|---|---|
| Hardcoded secrets | Regex patterns for AWS keys, Stripe live keys, GitHub tokens, Slack tokens, JWT/signing secrets, private key blocks |
| Vulnerable dependencies | `package.json` versions checked against a small hand-curated known-CVE list (seed data — production version should call a real OSV/CVE feed) |
| Missing lockfile | Checks for `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` |
| Missing privacy policy / terms | Looks for a root-level file matching the name |
| Undisclosed AI-generated content | Heuristic: content-generation-shaped code with no disclosure/C2PA marker nearby |
| Missing auth check | Heuristic: a file defining Express routes with no reference to a JWT/auth-middleware/passport call anywhere in it |

Every one of these is intentionally simple and will have false positives —
the point right now is a real, working, testable pipeline end to end, not
completeness. Next real gaps to close: wrap an actual OSS scanner (Semgrep,
gitleaks) instead of hand-rolled regex, and pull dependency vulnerabilities
from a live OSV feed instead of the hardcoded seed list.

## Architecture

See the full system diagram (this Tier 1 piece plus the Tier 2 "Open Water"
continuous monitoring, trust badge, and platform core that don't exist yet)
in the published artifact from the design pass.

## Known gap: sandboxing

The `/api/scans` endpoint currently extracts and reads the uploaded zip
directly on the host running the API. That's fine for local development —
it is **not** fine for production, since this endpoint runs static analysis
over code an attacker fully controls. Before this goes anywhere near real
traffic, extraction and scanning need to happen in an isolated, network-less
sandbox (see the AWS architecture notes: ECS Fargate tasks with no NAT/egress,
or a service like e2b/Modal purpose-built for executing untrusted code).
