import { Router, type Request, type Response } from "express";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import multer from "multer";
import { runScan } from "../scanner";
import { resolveScanRoot } from "../scanner/resolveScanRoot";
import { findProjectByApiKey } from "../patrol/projects";
import { createQueuedScan } from "../patrol/scans";
import { enqueueScan } from "../scanner/scanQueue";
import { requireAuth, optionalAuth } from "../auth/middleware";
import { entitledPlan } from "../billing/subscription";
import { resolveQuotaSubject } from "../billing/orgSubscription";
import { canRunScan, getMonthlyScanLimit } from "../billing/entitlements";
import { getUserById } from "../auth/users";
import { applyScanAccess } from "../billing/scanAccess";
import { hydrateCheckResults } from "../scanner/controls";
import type { ScanReport } from "../scanner/types";
import { getQuotaStateForSubject, recordQuotaUsage, reserveQuotaSlot, type QuotaSubject } from "../billing/scanQuota";
import type { Project } from "../patrol/types";
import { safeExtractZip } from "../scanner/safeExtraction";
import { rateLimit } from "../middleware/rateLimit";
import type { Request as ExpressRequest } from "express";

export const scansRouter = Router();

/**
 * Trims the report to what the plan is entitled to see (applyScanAccess),
 * then hydrates the checkResults that survive with a full recommendation —
 * quickFix/developerFix/architectureFix/verification/references — by
 * looking up each result's controlKey in the control library, technology-
 * matched against the report's own detectedTechnology.
 *
 * Hydration happens here, at the response boundary, the same as scan-access
 * trimming: the stored report stays the raw scan output, so a control
 * library update (new/changed recommendation text) is reflected on the next
 * read of an old scan without needing to rescan.
 *
 * A result with no controlKey (every check not yet migrated onto the
 * control library — see the scanner/controls/ gap report) comes back with
 * recommendation: null, not a fabricated one.
 */
function respondWithScan(res: Response, report: ScanReport, plan: string): void {
  const trimmed = applyScanAccess(report, plan);
  const hydrated = trimmed.checkResults
    ? hydrateCheckResults(trimmed.checkResults, { detectedTechnology: trimmed.detectedTechnology ?? undefined })
    : trimmed.checkResults;
  res.json({ ...trimmed, checkResults: hydrated });
}

/**
 * The entitlement gate in front of real scan execution. Returns the
 * QuotaSubject the caller should record usage against on success, or null
 * when the caller should stop (a response has already been sent).
 *
 * Anonymous, unauthenticated scans (billedUserId undefined — no bearer
 * token and no API key resolving to a project owner) have no account to
 * gate and stay preview-only, exactly as before: that pre-existing "try it
 * without an account" flow is a different thing from the FREE named plan
 * this pricing model governs, and is deliberately left untouched here.
 *
 * For an identified account (bearer token, or an API key whose project
 * resolves to an owner — so a CI run authenticated only by a project key is
 * gated the same as a browser session), the subject is resolved via
 * orgSubscription.ts's resolveQuotaSubject: the project's organization, if
 * it belongs to one that's actively subscribed itself (every member's
 * scans then draw from that organization's own shared monthly pool, not
 * their own personal number), else the billed account's own personal
 * quota — the pre-existing, unchanged behavior for a personal project or
 * an unsubscribed organization's project.
 *
 *   - FREE (canRunScan false, checked against the resolved subject's plan):
 *     blocked outright. This is the absolute rule the pricing model
 *     requires — FREE never gets a real scan, CLI/CI included, since both
 *     paths call this same route.
 *   - A finite monthly limit (BUILD, whichever subject holds it): the slot
 *     is reserved atomically via reserveQuotaSlot before any expensive work
 *     runs, so concurrent requests near the limit — whether from the same
 *     account or different members of the same organization — cannot both
 *     read "9 used, 10 allowed" and both proceed; see that function's own
 *     comment for how the atomicity works. A rejected reservation still
 *     costs nothing extra; the bucket it increments is enforcement-only,
 *     not the accurate usage figure shown in the UI (that's
 *     scan_usage/getQuotaStateForSubject, updated separately on an
 *     actually-completed scan via recordQuotaUsage below).
 *   - PROTECT (getMonthlyScanLimit returns null): unlimited/fair-use, no
 *     reservation needed. Still subject to scanUploadLimiter/scanRepoLimiter
 *     below — that's deliberately a separate concern (abuse/burst
 *     protection) from the subscription entitlement (unmetered), not a
 *     hidden numeric cap standing in for "unlimited".
 */
type ScanQuotaResolution =
  | { blocked: true }
  | { blocked: false; subject: null } // anonymous — no billedUserId, nothing to record against (unchanged pre-existing preview flow)
  | { blocked: false; subject: QuotaSubject };

async function resolveScanQuota(billedUserId: string | undefined, project: Pick<Project, "organizationId"> | null, res: Response): Promise<ScanQuotaResolution> {
  if (!billedUserId) return { blocked: false, subject: null };

  const owner = await getUserById(billedUserId);
  const { subject, plan } = await resolveQuotaSubject(billedUserId, project, entitledPlan(owner));

  if (!canRunScan(plan)) {
    res.status(402).json({
      error:
        "Scanning requires an active BUILD or PROTECT subscription. FREE accounts can explore Nettle's control library and sample findings, but never run a real scan.",
      subscriptionRequired: true,
      requiredPlan: "build",
      plan,
    });
    return { blocked: true };
  }

  const limit = getMonthlyScanLimit(plan);
  if (limit === null) return { blocked: false, subject }; // PROTECT: unlimited/fair-use

  const reserved = await reserveQuotaSlot(subject, limit);
  if (!reserved) {
    const quota = await getQuotaStateForSubject(subject, plan);
    res.status(402).json({
      error: `${subject.type === "organization" ? "Your organization has" : "You have"} used all ${limit} scans in this billing period.${
        quota ? ` Your allowance resets on ${new Date(quota.periodEnd).toLocaleDateString("en-GB")}.` : ""
      } Upgrade to PROTECT for unlimited, fair-use scanning.`,
      quotaExceeded: true,
      requiredPlan: "protect",
      limit,
      used: quota?.used ?? limit,
      remaining: 0,
      periodEnd: quota?.periodEnd ?? null,
    });
    return { blocked: true };
  }
  return { blocked: false, subject };
}

/**
 * Which plan governs this scan's report. A bearer token wins; failing that,
 * an API key identifies the owning project, and that project owner's plan
 * applies — so CI runs authenticated only by a project key still get the
 * full report the account pays for.
 */
async function planForScan(req: ExpressRequest, apiKeyProjectUserId?: string): Promise<string> {
  // entitledPlan, never user.plan/req.userPlan: a canceled or past_due
  // account keeps its plan recorded for reconciliation, and handing that
  // straight to applyScanAccess kept serving it the full paid report long
  // after it stopped paying.
  const bearerUser = req.userId ? await getUserById(req.userId) : null;
  if (bearerUser) return entitledPlan(bearerUser);
  if (apiKeyProjectUserId) {
    const owner = await getUserById(apiKeyProjectUserId);
    if (owner) return entitledPlan(owner);
  }
  return "free";
}

const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB — plenty for source code, not for asset-heavy repos
});

/**
 * Identity for the /api/scans burst limiter: prefer an authenticated identity
 * over the raw IP wherever one is available.
 *
 * Why this matters here specifically: a per-IP-only limiter would let one
 * customer's traffic count against a completely unrelated customer sharing
 * the same corporate gateway or CI network — an office NAT, a shared
 * GitHub-hosted runner pool, a VPN exit node. Keying by account (when known)
 * instead means each paying customer gets their own bucket regardless of who
 * else happens to share their egress IP that day.
 *
 * This does the same API-key -> project -> owner resolution the route
 * handler itself does; the DB call is duplicated once per request rather
 * than threading a resolved value through middleware, matching the existing
 * pattern in this file (planForScan does the equivalent lookup again).
 */
async function scanUploadIdentity(req: Request): Promise<string> {
  if (req.userId) return `user:${req.userId}`;
  const apiKey = req.header("x-nettle-api-key");
  if (apiKey) {
    const project = await findProjectByApiKey(apiKey);
    if (project) return `user:${project.userId}`;
  }
  return `ip:${req.ip ?? "unknown"}`;
}

/**
 * Anonymous, unauthenticated uploads bypass the monthly scan quota entirely
 * (resolveScanQuota() only gates known accounts), so this is the main thing
 * standing between the public upload endpoint and someone scripting
 * repeated Semgrep runs against it. Authenticated/API-key callers are
 * already metered monthly by billing/scanQuota — this is a second, much
 * shorter-window limit on top, guarding against a burst within one billing
 * period rather than total volume, since 30-60 scans arriving in the same
 * minute would still exhaust the container's CPU regardless of what the
 * monthly allowance says.
 */
const scanUploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  maxRequests: 20,
  message: "Too many scans submitted — try again in a few minutes",
  scope: "scans:upload",
  keyFn: scanUploadIdentity,
});

/**
 * /api/scans/repo always runs behind requireAuth, so req.userId is always
 * set by the time this executes — no IP fallback needed, and none wanted:
 * this is a paid, authenticated-only endpoint, so account-keying is strictly
 * correct here.
 */
const scanRepoLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  maxRequests: 10,
  message: "Too many repository scans submitted — try again in a few minutes",
  scope: "scans:repo",
  keyFn: (req) => (req.userId ? `user:${req.userId}` : null),
});

scansRouter.post("/api/scans", optionalAuth, scanUploadLimiter, upload.single("codebase"), async (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: "Upload a zip file under the 'codebase' field" });
  }
  if (path.extname(req.file.originalname).toLowerCase() !== ".zip") {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "Only .zip uploads are supported right now" });
  }

  // Resolve the billing account before doing any work — an over-quota
  // caller shouldn't get a scan run on their behalf and then be refused.
  const upfrontKey = req.header("x-nettle-api-key");
  const upfrontProject = upfrontKey ? await findProjectByApiKey(upfrontKey) : null;
  const billedUserId = req.userId ?? upfrontProject?.userId;
  const quota = await resolveScanQuota(billedUserId, upfrontProject, res);
  if (quota.blocked) {
    fs.unlinkSync(req.file.path);
    return;
  }

  const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-scan-"));

  // Extraction happens synchronously either way — it's the cheap,
  // security-critical step (symlink/decompression-bomb/path-traversal
  // checks) that must reject a bad archive before the caller is told
  // anything succeeded, async or not. What moves off the request path below
  // is the expensive part: actually running the scanner.
  let scanRoot: string;
  try {
    safeExtractZip(req.file.path, extractDir);
    scanRoot = resolveScanRoot(extractDir);
  } catch (err) {
    fs.unlinkSync(req.file.path);
    fs.rmSync(extractDir, { recursive: true, force: true });
    const msg = (err as Error).message;
    let statusCode = 422;
    let errorMsg = "Couldn't extract the uploaded file";

    if (msg.includes("symlink")) {
      statusCode = 400;
      errorMsg = "Archive contains symlinks, which are not allowed";
    } else if (msg.includes("absolute path") || msg.includes("path traversal")) {
      statusCode = 400;
      errorMsg = "Archive contains entries that would write outside the upload, which is not allowed";
    } else if (msg.includes("timeout")) {
      statusCode = 413;
      errorMsg = "Archive appears to be a decompression bomb or is too complex";
    } else if (msg.includes("exceeds limit")) {
      statusCode = 413;
      errorMsg = msg;
    }

    return res.status(statusCode).json({ error: errorMsg, detail: msg });
  }
  fs.unlinkSync(req.file.path); // the zip itself is no longer needed once extracted

  // Project-tied uploads run async: the record is created now, the client
  // gets its id back immediately, and the actual scan happens off the
  // request path via scanner/scanQueue.ts (see that file for exactly what
  // "async" does and doesn't mean here). Anonymous/no-project uploads keep
  // today's synchronous one-shot behavior unchanged — see
  // resolveScanQuota()'s comment for why that pre-existing flow is
  // deliberately untouched.
  if (upfrontProject) {
    const queued = await createQueuedScan(upfrontProject.id);
    if (quota.subject) await recordQuotaUsage(quota.subject, billedUserId!, upfrontProject.id, "upload");

    enqueueScan({
      scanId: queued.id,
      scanRoot,
      cleanup: () => fs.rmSync(extractDir, { recursive: true, force: true }),
    });

    return res.status(202).json({
      scanId: queued.id,
      projectId: upfrontProject.id,
      status: queued.status,
      message: "Scan queued — poll GET /api/projects/:id/scans or the project detail route for its status.",
    });
  }

  try {
    const report = runScan(scanRoot);
    if (quota.subject) await recordQuotaUsage(quota.subject, billedUserId!, null, "upload");
    respondWithScan(res, report, await planForScan(req));
  } catch (err) {
    const msg = (err as Error).message;
    res.status(422).json({ error: "Couldn't scan the uploaded file", detail: msg });
  } finally {
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
});

// The host allowlist lives in the pattern itself; a separate ALLOWED_HOSTS
// array duplicated it and was never read.
const REPO_URL_PATTERN = /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.\-]+\/[\w.\-]+(\.git)?$/;

// requireSubscription (account-level only) deliberately removed from this
// gate: resolveScanQuota below already calls canRunScan() against the
// correctly-resolved plan (the project's organization, if it's actively
// subscribed, else the caller's own — see that function's own comment) and
// responds 402 the same way, before any clone happens. Keeping
// requireSubscription here as well would 402 a FREE-personal member of a
// PROTECT-subscribed organization before resolveScanQuota ever got a
// chance to look past their personal plan — exactly the gap this pass
// closes. POST /api/scans (the upload route) never had this middleware and
// was already correctly org-aware for the same reason.
scansRouter.post("/api/scans/repo", requireAuth, scanRepoLimiter, async (req: Request, res: Response) => {
  const repoUrl = typeof req.body?.repoUrl === "string" ? req.body.repoUrl.trim() : "";
  const branch = typeof req.body?.branch === "string" ? req.body.branch.trim() : "";
  const apiKey = typeof req.body?.apiKey === "string" ? req.body.apiKey.trim() : "";

  if (!repoUrl) {
    return res.status(400).json({ error: "Provide a 'repoUrl' (e.g. https://github.com/owner/repo)" });
  }
  if (!REPO_URL_PATTERN.test(repoUrl)) {
    return res.status(400).json({ error: "Only public GitHub, GitLab, and Bitbucket HTTPS URLs are supported" });
  }

  const repoProject = apiKey ? await findProjectByApiKey(apiKey) : null;
  const billedUserId = req.userId ?? repoProject?.userId;
  const quota = await resolveScanQuota(billedUserId, repoProject, res);
  if (quota.blocked) return;

  const cloneDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-repo-"));

  // Cloning stays synchronous and on the request path — it's bounded (60s
  // timeout) and its own failure modes (repo not found, bad branch) need to
  // reach the caller as a clear error, not a queued job that fails
  // immediately after being accepted.
  try {
    const args = ["clone", "--depth", "1"];
    if (branch) args.push("--branch", branch);
    args.push(repoUrl, cloneDir);
    execFileSync("git", args, { timeout: 60_000, stdio: "pipe" });
  } catch (err) {
    fs.rmSync(cloneDir, { recursive: true, force: true });
    const msg = (err as Error).message;
    if (msg.includes("not found") || msg.includes("Could not read")) {
      return res.status(404).json({ error: "Repository not found — check the URL and make sure it's public" });
    }
    if (msg.includes("not a valid branch") || msg.includes("Remote branch")) {
      return res.status(400).json({ error: `Branch '${branch}' not found in the repository` });
    }
    return res.status(422).json({ error: "Couldn't clone the repository", detail: msg });
  }

  // Same split as POST /api/scans: a project-tied clone runs the actual
  // scan async, off the request path; a project-less one (bearer-token-only,
  // no project apiKey supplied) stays synchronous — see scanQueue.ts.
  if (repoProject) {
    const queued = await createQueuedScan(repoProject.id);
    if (quota.subject) await recordQuotaUsage(quota.subject, billedUserId!, repoProject.id, "repo");

    enqueueScan({
      scanId: queued.id,
      scanRoot: cloneDir,
      cleanup: () => fs.rmSync(cloneDir, { recursive: true, force: true }),
    });

    return res.status(202).json({
      scanId: queued.id,
      projectId: repoProject.id,
      status: queued.status,
      message: "Scan queued — poll GET /api/projects/:id/scans or the project detail route for its status.",
    });
  }

  try {
    const report = runScan(cloneDir);
    if (quota.subject) await recordQuotaUsage(quota.subject, billedUserId!, null, "repo");
    respondWithScan(res, report, await planForScan(req));
  } catch (err) {
    res.status(422).json({ error: "Couldn't scan the repository", detail: (err as Error).message });
  } finally {
    fs.rmSync(cloneDir, { recursive: true, force: true });
  }
});
