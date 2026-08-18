# @nettle/cli

The full-featured Nettle CLI: authenticate, manage projects, scan a local
directory or a public Git repo against the real Nettle API, and gate CI/CD
pipelines on the result.

For a local-only, offline scan that never uploads your code anywhere (but
has no project management or repo scanning), see
[`../backend/bin/nettle.js`](../backend/README.md) instead — installed as
`nettle-local` to avoid colliding with this package's own `nettle` bin.

## Install

```bash
cd cli
npm install
npm link          # installs the `nettle` command globally
```

Or run it without linking:

```bash
node bin/nettle.js <command>
```

By default the CLI talks to `http://localhost:8080`. Override this per
command with `--api-url <url>`, or persist it by setting `apiUrl` in
`~/.nettle/config.json` (created automatically on first `login`).

## Commands

### Auth

```bash
nettle signup              # create an account, stores the session token
nettle login                # log in, stores the session token
nettle whoami                # show the current logged-in user
nettle logout                # clear the stored token
```

The session token is stored in `~/.nettle/config.json`. `scan` does **not**
require login (it can run against a project via `--api-key` alone, or fully
anonymously); `scan-repo`, `projects`, and `history` do.

### Projects

```bash
nettle projects                    # list your projects
nettle projects create <name>      # create one; prints its API key
```

### Scanning

```bash
nettle scan [path]                 # scan a local directory (default: cwd)
nettle scan-repo <url>             # clone and scan a public Git repo
```

Both accept:

| Flag | Purpose |
|---|---|
| `--api-key <key>` | Associate the scan with a project (from `nettle projects create`) |
| `--json` | Print the raw JSON report instead of the formatted human output |
| `--fail-on <severity>` | Exit `1` if any finding is at or above `critical`\|`high`\|`medium`\|`low`. **Omitted by default** — without this flag the process always exits `0` regardless of findings, so a CI job that wants to gate on results must pass it explicitly. |
| `--branch <branch>` | (`scan-repo` only) branch to scan; defaults to the repo's default branch |

`scan` zips the target directory (excluding `node_modules/`, `.git/`,
`dist/`, `build/`, `.next/`, `__pycache__/`, `.venv/`, `vendor/`) and
uploads it to `POST /api/scans` — this requires the `zip` binary on your
`PATH`. `scan-repo` sends the URL to the backend, which clones and scans it
server-side.

### History

```bash
nettle history <project-id>        # scan history for a project
```

## CI/CD example

```bash
nettle scan . --api-key "$NETTLE_API_KEY" --fail-on high --json > report.json
```

Exits non-zero (failing the job) if the scan found any `high` or `critical`
finding; the JSON report is saved either way for later inspection.

## Develop

```bash
npm test        # node:test — real assertions on the CLI's output
                 # formatting (cli/src/format.js)
```

End-to-end coverage (a real `nettle login` + `nettle scan` run as an actual
child process against a real, ephemeral backend server — not mocked) lives
in the backend test suite: `backend/test/cliIntegration.test.ts`. It's
there rather than here because it needs the backend's own tsx/TypeScript
test tooling to boot a real server in-process.
