import { Router, type Request, type Response } from "express";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import multer from "multer";
import { runScan } from "../scanner";
import { resolveScanRoot } from "../scanner/resolveScanRoot";
import { findProjectByApiKey } from "../patrol/projects";
import { recordScan } from "../patrol/scans";
import { requireAuth, optionalAuth } from "../auth/middleware";
import { requireSubscription, entitledPlan } from "../billing/subscription";
import { canRunScan, getMonthlyScanLimit } from "../billing/entitlements";
import { getUserById } from "../auth/users";
import { applyScanAccess } from "../billing/scanAccess";
import { hydrateCheckResults } from "../scanner/controls";
import type { ScanReport } from "../scanner/types";
import { getQuotaState, recordScanUsage, reserveScanSlot } from "../billing/scanQuota";
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
 * The entitlement gate in front of real scan execution. Returns true when
 * the caller should stop (a response has already been sent).
 *
 * Anonymous, unauthenticated scans (billedUserId undefined — no bearer
 * token and no API key resolving to a project owner) have no account to
 * gate and stay preview-only, exactly as before: that pre-existing "try it
 * without an account" flow is a different thing from the FREE named plan
 * this pricing model governs, and is deliberately left untouched here.
 *
 * For an identified account (bearer token, or an API key whose project
 * resolves to an owner — so a CI run authenticated only by a project key is
 * gated the same as a browser session):
 *   - FREE (canRunScan false): blocked outright. This is the absolute rule
 *     the pricing model requires — FREE never gets a real scan, CLI/CI
 *     included, since both paths call this same route.
 *   - BUILD (a finite monthly limit): the slot is reserved atomically via
 *     reserveScanSlot before any expensive work runs, so two concurrent
 *     requests near the limit cannot both read "9 used, 10 allowed" and
 *     both proceed — see that function's comment for how the atomicity
 *     works. A rejected reservation still costs nothing extra; the bucket
 *     it increments is enforcement-only, not the accurate usage figure
 *     shown in the UI (that's scan_usage/getQuotaState, updated separately
 *     on an actually-completed scan via recordScanUsage below).
 *   - PROTECT (getMonthlyScanLimit returns null): unlimited/fair-use, no
 *     reservation needed. Still subject to scanUploadLimiter/scanRepoLimiter
 *     below — that's deliberately a separate concern (abuse/burst
 *     protection) from the subscription entitlement (unmetered), not a
 *     hidden numeric cap standing in for "unlimited".
 */
async function scanBlocked(billedUserId: string | undefined, res: Response): Promise<boolean> {
  if (!billedUserId) return false;

  const owner = await getUserById(billedUserId);
  const plan = entitledPlan(owner);

  if (!canRunScan(plan)) {
    res.status(402).json({
      error:
        "Scanning requires an active BUILD or PROTECT subscription. FREE accounts can explore Nettle's control library and sample findings, but never run a real scan.",
      subscriptionRequired: true,
      requiredPlan: "build",
      plan,
    });
    return true;
  }

  const limit = getMonthlyScanLimit(plan);
  if (limit === null) return false; // PROTECT: unlimited/fair-use

  const reserved = await reserveScanSlot(billedUserId, limit);
  if (!reserved) {
    const quota = await getQuotaState(billedUserId);
    res.status(402).json({
      error: `You have used all ${limit} scans in this billing period.${
        quota ? ` Your allowance resets on ${new Date(quota.periodEnd).toLocaleDateString("en-GB")}.` : ""
      } Upgrade to PROTECT for unlimited, fair-use scanning.`,
      quotaExceeded: true,
      requiredPlan: "protect",
      limit,
      used: quota?.used ?? limit,
      remaining: 0,
      periodEnd: quota?.periodEnd ?? null,
    });
    return true;
  }
  return false;
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
 * (scanBlocked() only gates known accounts), so this is the main thing
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
  if (await scanBlocked(billedUserId, res)) {
    fs.unlinkSync(req.file.path);
    return;
  }

  const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-scan-"));
  try {
    safeExtractZip(req.file.path, extractDir);
    const scanRoot = resolveScanRoot(extractDir);
    const report = runScan(scanRoot);

    // Optional: if the request identifies a project (same API key the
    // monitoring middleware uses), persist the scan against it so the badge
    // and dashboard have real history. Scanning without a project is still
    // fully supported — a quick one-off check needs no account at all.
    //
    // Note the full report is what gets stored; only the response is trimmed
    // to the caller's plan, so upgrading later unlocks this scan in place.
    let ownerUserId: string | undefined;
    if (upfrontProject) {
      await recordScan(upfrontProject.id, report);
      ownerUserId = upfrontProject.userId;
    }

    if (billedUserId) await recordScanUsage(billedUserId, upfrontProject?.id ?? null, "upload");

    respondWithScan(res, report, await planForScan(req, ownerUserId));
  } catch (err) {
    const msg = (err as Error).message;
    let statusCode = 422;
    let errorMsg = "Couldn't extract or scan the uploaded file";

    if (msg.includes("symlink")) {
      statusCode = 400;
      errorMsg = "Archive contains symlinks, which are not allowed";
    } else if (msg.includes("absolute path") || msg.includes("path traversal")) {
      // Caller error, not a server failure: the archive is malformed in a way
      // we deliberately refuse, so say so rather than returning a generic 422.
      statusCode = 400;
      errorMsg = "Archive contains entries that would write outside the upload, which is not allowed";
    } else if (msg.includes("timeout")) {
      statusCode = 413;
      errorMsg = "Archive appears to be a decompression bomb or is too complex";
    } else if (msg.includes("exceeds limit")) {
      statusCode = 413;
      errorMsg = msg; // Use the specific limit message
    }

    res.status(statusCode).json({ error: errorMsg, detail: msg });
  } finally {
    fs.unlinkSync(req.file.path);
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
});

// The host allowlist lives in the pattern itself; a separate ALLOWED_HOSTS
// array duplicated it and was never read.
const REPO_URL_PATTERN = /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.\-]+\/[\w.\-]+(\.git)?$/;

scansRouter.post("/api/scans/repo", requireAuth, scanRepoLimiter, requireSubscription, async (req: Request, res: Response) => {
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
  if (await scanBlocked(billedUserId, res)) return;

  const cloneDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-repo-"));
  try {
    const args = ["clone", "--depth", "1"];
    if (branch) args.push("--branch", branch);
    args.push(repoUrl, cloneDir);

    execFileSync("git", args, { timeout: 60_000, stdio: "pipe" });

    const report = runScan(cloneDir);

    let ownerUserId: string | undefined;
    if (repoProject) {
      await recordScan(repoProject.id, report);
      ownerUserId = repoProject.userId;
    }

    if (billedUserId) await recordScanUsage(billedUserId, repoProject?.id ?? null, "repo");

    respondWithScan(res, report, await planForScan(req, ownerUserId));
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes("not found") || msg.includes("Could not read")) {
      return res.status(404).json({ error: "Repository not found — check the URL and make sure it's public" });
    }
    if (msg.includes("not a valid branch") || msg.includes("Remote branch")) {
      return res.status(400).json({ error: `Branch '${branch}' not found in the repository` });
    }
    res.status(422).json({ error: "Couldn't clone or scan the repository", detail: msg });
  } finally {
    fs.rmSync(cloneDir, { recursive: true, force: true });
  }
});
