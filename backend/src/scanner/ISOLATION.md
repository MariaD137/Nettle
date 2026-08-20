# Scanner isolation architecture

## What this document is

The design for moving untrusted-repository scanning out of the main
Nettle API process and into a disposable, isolated ECS Fargate task. This
covers the security boundary, the job/data flow, IAM, networking, limits,
and — explicitly — what has been verified locally versus what still
requires a real AWS account to exercise. See `test/*.test.ts` for the
runnable proof of every claim marked "verified locally" below.

## The actual risk, stated plainly

Nettle's scanners (`src/scanner/*`) never run `npm install`, never execute
a customer's build/lifecycle scripts, and never invoke a customer-supplied
binary — that was already true before this change (confirmed by reading
every `execFileSync`/`exec`/`spawn` call site in `src/scanner/`: only
`git`, `unzip`, and `semgrep`, all trusted binaries with controlled
arguments, are ever invoked; see `AUDIT.md`-style notes inline in this
document's "Inspection findings" section below). Semgrep and every other
check receive extracted files as data — static parsing, not execution.

The real risk is different: **extraction and static analysis themselves
are attack surface.** A maliciously crafted zip or git repository is
adversarial input to `unzip`, `git clone`, Node's own file-walking code,
and Semgrep's parsers — any bug in any of those (a decompression bomb, a
path-traversal edge case, a parser crash-to-RCE) currently executes with
the same OS-level privileges as the rest of the API process, in the same
container, on the same host, with network access to RDS and every other
internal service. `workerIsolation.ts` (removed in an earlier pass — see
git history) never actually closed this gap: it was dead code, never wired
into the real scan pipeline, and even if it had been wired in,
`worker_threads` share the host process's OS-level privileges — a thread
boundary is not a security boundary, and this document does not claim
otherwise (see "What this is not" below).

## The boundary: a disposable Fargate task, not a thread

```
App Runner (main API process)
  │  never touches customer-supplied file bytes
  │  never runs unzip/git/semgrep against them
  ▼
Scan job created, input handed off
  ▼
ECS Fargate task (new process, new container, new microVM)
  │  non-root user, read-only root filesystem, capabilities dropped
  │  no route to RDS, Secrets Manager, App Runner, Cognito
  │  no application/database/Stripe credentials of any kind
  ├── obtain scan input (S3 download, or git clone over the network)
  ├── extract safely (existing safeExtraction.ts limits, unchanged)
  ├── run the same static-analysis pipeline (src/scanner/index.ts, unchanged)
  ├── POST the result back to the API via a single-use, per-job callback token
  └── terminate — task and all its storage cease to exist
  ▼
Trusted API records the result, customer polls/retrieves it
```

Fargate tasks run in their own microVM (Firecracker) per AWS's own
architecture — this is the real isolation boundary being relied on, not a
CDK setting. What CDK/the task definition *do* control, and what's
actually configured here: no inbound network reachability, egress
restricted to what a scan genuinely needs, a dedicated IAM role with
exactly two permissions (see IAM below), non-root execution, a read-only
root filesystem, dropped Linux capabilities, and hard resource/time
ceilings so a single malicious input can't consume unbounded CPU/memory/
disk or run indefinitely.

## What this is *not* (per explicit instruction not to fake security)

- **Not** "worker threads are a sandbox." They aren't used for the
  isolation boundary at all any more when `NETTLE_SCANNER_BACKEND=fargate`
  is set — see below for why they still exist as the local/default path.
- **Not** "Docker alone makes this safe." A container sharing a kernel
  with other tasks is not the claim; Fargate's per-task microVM isolation
  is what's actually relied on, and that's an AWS platform property, not
  something this repository's code creates.
- **Not** "memory limits are sandboxing." The Fargate task's CPU/memory/
  ephemeral-storage limits (below) bound resource *exhaustion*, the same
  honest framing `jobs/scanJobs.ts`'s existing worker `resourceLimits`
  already used — they are not a substitute for the process/network
  isolation boundary itself.

## Two backends, one contract

`src/scanner/isolatedRunner.ts` exports one function,
`runScanIsolated(input, onProgress?): Promise<ScanReport>`, with two
implementations selected by `NETTLE_SCANNER_BACKEND`:

- **`worker_thread` (default, unset).** The existing, unchanged
  `jobs/scanJobs.ts` worker-thread path (`scanWorker.ts`). This is *not*
  claimed as the security boundary — it exists so local development, CI,
  and this sandbox (which has no AWS account to launch a real Fargate
  task against) keep working exactly as before, with zero behavior change
  for anyone not running in an AWS environment with the scanner stack
  deployed. Nothing about this document's security claims applies while
  this backend is selected; that's stated explicitly here, not implied.
- **`fargate`.** Launches a real ECS Fargate task (`src/jobs/fargateScanner.ts`,
  using `@aws-sdk/client-ecs`'s `RunTaskCommand`) and awaits its callback.
  This is the real isolation boundary described above. Selected by setting
  `NETTLE_SCANNER_BACKEND=fargate` on the API's environment — done in
  `infra/lib/api-stack.ts` once a human has actually deployed the scanner
  stack (see REQUIRES AWS CONFIGURATION notes there); never the default.

Both the synchronous scan routes (`POST /api/scans`, `/api/scans/repo` —
used by the CLI/CI, which expects the full report back in one response)
and the async scan-job routes (`POST /api/scans/jobs/*` — used by the web
UI's polling flow) call the same `runScanIsolated()`, so the isolation
boundary applies to every code path that touches customer-supplied source,
not just the async one. `POST /api/scans/url` is deliberately excluded:
it never extracts or parses customer-supplied files at all — it only
issues SSRF-guarded outbound HTTP requests via the existing
`ssrfSafeFetch` (untouched by this change) and inspects response headers/
TLS, a materially different and already-mitigated threat model.

## Data flow detail

**Zip upload:** the API uploads the raw zip to a dedicated, private S3
bucket (`ScanInputBucket`, lifecycle-expires objects after 1 day as
defense in depth) under `uploads/<jobId>.zip`, then runs the task with
that key as an env var override. The task downloads it, scans, and the
API deletes the object once the task reports success or failure — the
task's own IAM role can `GetObject`/`DeleteObject` on that one prefix
only, nothing else in the bucket or account.

**Repo scan:** the already-decrypted repo access token (decryption still
happens API-side via the existing `security/tokenEncryption.ts`, unchanged)
is passed as a one-off `RunTaskCommand` environment override — scoped to
that single task invocation, never baked into the task definition or the
container image, and gone once the task terminates. This is the same
token, at the same trust level, that already crossed a process boundary
into `cloneRepo()`'s child `git` process before this change; it now
crosses one more boundary (network, to the task) instead of a local one.

**Result delivery:** the task POSTs its `ScanReport` (or an error) to
`POST /api/internal/scan-tasks/:jobId/result` (`internal.routes.ts`),
authenticated by a random, single-use, per-job callback token generated
by the API when the job is created and passed to the task the same way —
never a database credential, never `CRON_SECRET`, never any other secret
the task doesn't need for this one job. The token is consumed (deleted
from the pending-job registry) on first use; a replay is rejected.

## IAM (least privilege)

**Scanner task role** (what the running container can do):
- `s3:GetObject`, `s3:DeleteObject` on `arn:...:s3:::<bucket>/uploads/*` only.
- Nothing else. No `secretsmanager:*`, no `rds:*`, no `ecs:*`, no
  wildcard resource. See `infra/lib/scanner-stack.ts`.

**Scanner execution role** (what ECS itself needs to start the task):
- ECR image pull (scoped to the one scanner repository) + CloudWatch Logs
  write (scoped to the one log group) — the standard minimal ECS
  execution-role shape, nothing broader.

**API instance role additions** (what the trusted API needs to launch a
scan task):
- `ecs:RunTask` scoped to the scanner task definition's family ARN.
- `iam:PassRole` scoped to exactly the scanner task role + execution role
  ARNs (required by ECS to launch a task on the caller's behalf) — not a
  wildcard `iam:PassRole` on `*`.
- `s3:PutObject` on the input bucket's `uploads/*` prefix only.

## Networking

The scanner task runs in the same VPC's private, NAT-egress subnets as
the API (`NettleNetworkStack`), but in its **own** security group
(`ScannerSecurityGroup`) — not the API's `connectorSecurityGroup`, and
critically, RDS's security group only allows inbound from
`connectorSecurityGroup` (`database-stack.ts`, unchanged), so the scanner
task has no network path to RDS, and none was added. No ingress rules
exist on the scanner security group at all — the task never accepts
inbound connections; it only makes outbound calls itself (to S3, to
whichever git host a repo scan targets, and its own callback POST to the
API's public App Runner URL).

**Outbound internet access is required**, for two legitimate reasons: (1)
cloning a customer's git repository, which can be hosted anywhere, and
(2) reaching the API's public endpoint to deliver the callback (the task
has no private path to App Runner's internal address space, so this goes
out through the NAT gateway and back in through App Runner's public
endpoint — the same network path an external caller would use, just
authenticated by the per-job callback token instead of a session). This
is not narrowed further than "outbound, NAT-gated, no inbound" because a
repo scan's destination host is inherently caller-controlled and can't be
allowlisted in advance; URL-target requests continue to go through
`ssrfSafeFetch`'s DNS-rebinding-safe validation exactly as before,
unrelated to this task's own git-clone egress.

## Limits

All enforced in `taskEntrypoint.ts` / the Fargate task definition:

| Limit | Value | Enforced by |
|---|---|---|
| Task CPU | 1 vCPU | Fargate task definition |
| Task memory | 2 GB | Fargate task definition |
| Ephemeral storage | 21 GB (Fargate's own minimum/default) | Fargate task definition |
| Task wall-clock timeout | ~10 minutes | entrypoint watchdog + orchestrator timeout + `ecs:StopTask` (see below — not a native Fargate "max task duration" setting, which doesn't exist for standalone `RunTask`) |
| Uncompressed archive size | 500 MB | `safeExtraction.ts` (unchanged, existing) |
| Extracted file count | 10,000 | `safeExtraction.ts` (unchanged, existing) |
| Directory depth | 100 | `safeExtraction.ts` + `walk.ts` (unchanged, existing) |
| Individual file size | 50 MB | **new** — added to `safeExtraction.ts` as part of this change |
| Zip decompression ratio / timeout | 30s extraction timeout | `safeExtraction.ts` (unchanged, existing) |

The per-file-size cap is new; every other limit already existed in
`safeExtraction.ts` from prior work and is unchanged here — moving the
process boundary doesn't relax any application-level limit that already
existed.

## Failure handling

- **Task launch failure** (`RunTaskCommand` itself fails, or returns
  `failures[]`): the job is marked failed immediately, no task was ever
  running, nothing to clean up.
- **Task timeout**: there is no native Fargate/ECS "maximum task
  duration" setting for a standalone `RunTask` — the wall-clock ceiling
  here is entirely software, layered three ways: `taskEntrypoint.ts`'s own
  9-minute internal watchdog (the task posts a failure callback and exits
  on its own before anything external has to act), `fargateScanner.ts`'s
  `registerPendingScan` timeout (~10 minutes — rejects the orchestrator's
  promise if no callback ever arrives), and `jobs/scanJobs.ts`'s
  pre-existing `jobTimeoutMs()` ceiling for jobs launched through the
  async job queue. Any of the latter two firing calls `job.cancelFn`,
  which for a Fargate-backed job is `stopFargateScanTask` —
  `ecs:StopTask`, scoped to this cluster (see `api-stack.ts`'s
  `ApiInstanceRoleDefaultPolicy`) — so the task is actually told to stop,
  not just abandoned. `stopTimeout` on the task definition (30s) is a
  different thing: the grace period ECS gives the container to exit
  cleanly after that stop signal before it's killed outright, not the
  wall-clock ceiling itself.
- **Task crash / scanner process failure**: `taskEntrypoint.ts` wraps its
  whole body in try/catch, same as `scanWorker.ts` does today, and POSTs
  an error result on any exception. If the container exits without ever
  calling back (OOM-killed, killed by Fargate's own health/resource
  enforcement), the timeout above catches it.
- **Malicious archive / oversized repo / excessive file count**: the
  existing `safeExtraction.ts` checks run inside the task exactly as they
  ran in-process before; a rejection there is caught and reported as a
  normal scan failure, not a task crash.
- **Duplicate scan request**: unchanged — `jobs/scanJobs.ts`'s existing
  job-id-per-request model already handles this; nothing about moving the
  execution backend changes request/job semantics.
- **Cancellation**: `cancelScanJob()` for a Fargate-backed job calls
  `ecs:StopTask` on the running task (a real, scoped permission the API
  role does need for this — see IAM above) instead of `worker.terminate()`.

## Cleanup

- The S3 input object is deleted by the API once the task reports success
  or failure (belt-and-suspenders on top of the bucket's own 1-day
  lifecycle expiry, in case the delete call itself fails).
- The task's own ephemeral storage — including the extracted archive, the
  git clone, and any temp files `safeExtraction.ts`/`gitAuth.ts` create —
  ceases to exist the moment the task stops; Fargate does not reuse task
  filesystems across invocations, so there is no "clean up the temp
  directory" step that can be skipped or fail silently the way a
  long-lived host's `/tmp` could accumulate leftovers.
- No customer repository content is ever written to the API's own
  filesystem when the fargate backend is active — extraction happens
  entirely inside the disposable task.

## Cost

Fargate is billed per-second while a task runs, not for idle capacity —
there is no permanently-running scanner instance, no reserved capacity,
no Multi-AZ requirement introduced. Cost drivers, in order of impact: (1)
scan volume × average scan duration × the 1 vCPU/2GB rate, (2) the single
NAT gateway's per-GB data-processing charge for git clones and the
callback POST (shared with the API's own existing egress — no new NAT
gateway added), (3) CloudWatch Logs ingestion/storage for task logs
(bounded by a retention policy on the log group), (4) negligible S3
storage (objects live at most ~1 day). No ECS cluster capacity is
reserved — `ecs.Cluster` with only Fargate capacity providers has no
standing EC2 cost.

## What's verified locally vs. requires AWS

**Verified locally** (see `test/` for the actual test files): the
callback-token generation/validation/single-use logic, the pending-scan
promise registry (register/resolve/reject/timeout), `RunTaskCommand`'s
parameters being constructed correctly (asserted against a stubbed ECS
client — no real AWS call made), the new per-file-size limit in
`safeExtraction.ts`, `isolatedRunner.ts`'s backend selection, and that
every existing scan-route/job-route test still passes with the
`worker_thread` backend (the default, and the only one actually
exercisable without a real AWS account).

**Requires AWS, not done here:** actually deploying `scanner-stack.ts`
(`cdk deploy`), building and pushing the scanner-task image to its ECR
repo, running a real Fargate task, verifying its actual outbound network
behavior (NAT egress, no path to RDS) against a live VPC, and verifying
IAM permissions are sufficient/correctly scoped against a real AWS API
response rather than by source-code review. `cdk synth` (template
generation only, no AWS calls) is run and its output checked — see the
final report.
