import { Router, type Request, type Response } from "express";
import fs from "fs";
import os from "os";
import path from "path";
import multer from "multer";
import { runUrlScan, SsrfBlockedError, UrlScanUnreachableError } from "../scanner";
import { runScanIsolated } from "../scanner/isolatedRunner";
import { findProjectByApiKeyForScope, getDecryptedRepoAccessToken } from "../patrol/projects";
import { recordScan } from "../patrol/scans";
import { requireAuth, optionalAuth } from "../auth/middleware";
import { requireSubscription } from "../billing/subscription";
import { resolveEntitlement } from "../billing/entitlement";
import { applyScanAccess } from "../billing/scanAccess";
import { reserveScanUsage, releaseScanUsage } from "../billing/scanQuota";
import { scanRateLimit } from "../middleware/rateLimit";
import { asyncHandler } from "../middleware/asyncHandler";
import type { Request as ExpressRequest } from "express";

export const scansRouter = Router();

/**
 * Atomically reserves one unit of scan usage (see reserveScanUsage in
 * billing/scanQuota.ts) and, if the account is metered and already at its
 * limit, sends the 402 response itself. Anonymous, unauthenticated scans
 * have no account to meter and are preview-only, so they always proceed.
 *
 * Returns the reservation's usageId so the caller can releaseScanUsage()
 * it if the scan this was reserved for doesn't actually succeed — a failed
 * attempt still shouldn't count against the allowance.
 */
export async function reserveOrRespond(
  userId: string | undefined,
  projectId: string | null,
  source: "upload" | "repo" | "url",
  res: Response
): Promise<{ proceed: boolean; usageId: string | null }> {
  const { blocked, usageId, quota } = await reserveScanUsage(userId, projectId, source);
  if (blocked && quota) {
    res.status(402).json({
      error: `You have used all ${quota.limit} scans in this billing period. Your allowance resets on ${new Date(quota.periodEnd).toLocaleDateString("en-GB")}.`,
      quotaExceeded: true,
      limit: quota.limit,
      used: quota.used,
      remaining: 0,
      periodEnd: quota.periodEnd,
    });
    return { proceed: false, usageId: null };
  }
  return { proceed: true, usageId };
}

/**
 * Which entitlement governs this scan's report. A bearer token wins;
 * failing that, an API key identifies the owning project, and that project
 * owner's entitlement applies — so CI runs authenticated only by a project
 * key still get the full report the account pays for. Always re-resolved
 * from the database (see resolveEntitlement) rather than trusting a value
 * cached earlier in the request, so a lapsed subscription is honored
 * immediately rather than on whatever refreshed req.userPlan last.
 */
export async function planForScan(req: ExpressRequest, apiKeyProjectUserId?: string) {
  return resolveEntitlement(req.userId, apiKeyProjectUserId);
}

export const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB — plenty for source code, not for asset-heavy repos
});

scansRouter.post("/api/scans", optionalAuth, scanRateLimit, upload.single("codebase"), asyncHandler(async (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: "Upload a zip file under the 'codebase' field" });
  }
  if (path.extname(req.file.originalname).toLowerCase() !== ".zip") {
    fs.rmSync(req.file.path, { force: true });
    return res.status(400).json({ error: "Only .zip uploads are supported right now" });
  }

  // Resolve the billing account before doing any work — an over-quota
  // caller shouldn't get a scan run on their behalf and then be refused.
  // reserveOrRespond reserves the usage slot atomically right here, before
  // any of the slow extraction/scan work below — see billing/scanQuota.ts.
  const upfrontKey = req.header("x-nettle-api-key");
  const upfrontProject = upfrontKey ? await findProjectByApiKeyForScope(upfrontKey, "scan") : null;
  const billedUserId = req.userId ?? upfrontProject?.userId;
  const { proceed, usageId } = await reserveOrRespond(billedUserId, upfrontProject?.id ?? null, "upload", res);
  if (!proceed) {
    fs.rmSync(req.file.path, { force: true });
    return;
  }

  try {
    // Extraction and scanning both happen outside this process now — see
    // scanner/isolatedRunner.ts and scanner/ISOLATION.md. Neither backend
    // it might select ever hands untrusted archive content back to this
    // route; only the finished ScanReport crosses back.
    const report = await runScanIsolated({ mode: "upload", zipPath: req.file.path });

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

    res.json(applyScanAccess(report, await planForScan(req, ownerUserId)));
  } catch (err) {
    // The reserved usage slot was for a scan that didn't actually succeed
    // — refund it, preserving "only successful scans count against quota".
    await releaseScanUsage(usageId);

    const msg = (err as Error).message;
    let statusCode = 422;
    let errorMsg = "Couldn't extract or scan the uploaded file";

    if (msg.includes("symlink")) {
      statusCode = 400;
      errorMsg = "Archive contains symlinks, which are not allowed";
    } else if (msg.includes("timeout")) {
      statusCode = 413;
      errorMsg = "Archive appears to be a decompression bomb or is too complex";
    } else if (msg.includes("exceeds limit")) {
      statusCode = 413;
      errorMsg = msg; // Use the specific limit message
    }

    res.status(statusCode).json({ error: errorMsg, detail: msg });
  } finally {
    // Both isolatedRunner backends already delete req.file.path themselves
    // once they've consumed it (the worker thread's own finally block, or
    // fargateScanner.ts right after its S3 upload) — this is a
    // defense-in-depth fallback for any path that returned before that
    // happened (the validation/quota checks above); force:true makes a
    // second delete of an already-gone file a no-op instead of an error.
    fs.rmSync(req.file.path, { force: true });
  }
}));

const ALLOWED_HOSTS = ["github.com", "gitlab.com", "bitbucket.org"];
export const REPO_URL_PATTERN = /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.\-]+\/[\w.\-]+(\.git)?$/;

scansRouter.post("/api/scans/repo", requireAuth, requireSubscription, scanRateLimit, asyncHandler(async (req: Request, res: Response) => {
  const repoUrl = typeof req.body?.repoUrl === "string" ? req.body.repoUrl.trim() : "";
  const branch = typeof req.body?.branch === "string" ? req.body.branch.trim() : "";
  const apiKey = typeof req.body?.apiKey === "string" ? req.body.apiKey.trim() : "";

  if (!repoUrl) {
    return res.status(400).json({ error: "Provide a 'repoUrl' (e.g. https://github.com/owner/repo)" });
  }
  if (!REPO_URL_PATTERN.test(repoUrl)) {
    return res.status(400).json({ error: "Only GitHub, GitLab, and Bitbucket HTTPS URLs are supported" });
  }

  const repoProject = apiKey ? await findProjectByApiKeyForScope(apiKey, "scan") : null;
  const billedUserId = req.userId ?? repoProject?.userId;
  const { proceed, usageId } = await reserveOrRespond(billedUserId, repoProject?.id ?? null, "repo", res);
  if (!proceed) return;

  // A project with a stored access token can have its private repo scanned;
  // anonymous or token-less requests still work exactly as before for
  // public repos. The token is decrypted only here, used only in-process by
  // git, and never touches a log line, an error message, or the response.
  const repoToken = repoProject ? await getDecryptedRepoAccessToken(repoProject.id) : null;

  try {
    // Cloning and scanning both happen outside this process now — see
    // scanner/isolatedRunner.ts and scanner/ISOLATION.md. No cloneDir or
    // finally-cleanup is needed here any more: the isolated worker/task
    // owns its own clone directory (or container filesystem) end to end
    // and removes it as part of its own cleanup.
    const report = await runScanIsolated({ mode: "repo", repoUrl, branch, token: repoToken });

    let ownerUserId: string | undefined;
    if (repoProject) {
      await recordScan(repoProject.id, report);
      ownerUserId = repoProject.userId;
    }

    res.json(applyScanAccess(report, await planForScan(req, ownerUserId)));
  } catch (err) {
    await releaseScanUsage(usageId);

    const msg = (err as Error).message;
    if (msg.includes("not found") || msg.includes("Could not read")) {
      return res.status(404).json({ error: "Repository not found — check the URL and make sure it's public" });
    }
    if (msg.includes("not a valid branch") || msg.includes("Remote branch")) {
      return res.status(400).json({ error: `Branch '${branch}' not found in the repository` });
    }
    res.status(422).json({ error: "Couldn't clone or scan the repository", detail: msg });
  }
}));

/**
 * URL scanning is external, non-destructive, black-box observation only —
 * it never sees source code, so it must never be presented as if it had.
 * Because it makes Nettle's own infrastructure issue outbound requests to
 * an address the caller supplies, this route requires a logged-in account
 * (for abuse accountability and quota metering) and an explicit ownership/
 * authorization confirmation, unlike the anonymous-friendly zip upload.
 */
scansRouter.post("/api/scans/url", requireAuth, scanRateLimit, asyncHandler(async (req: Request, res: Response) => {
  const targetUrl = typeof req.body?.url === "string" ? req.body.url.trim() : "";
  const confirmed = req.body?.confirmed === true;

  if (!targetUrl) {
    return res.status(400).json({ error: "Provide a 'url' to scan" });
  }
  if (!confirmed) {
    return res.status(400).json({
      error: "You must confirm that you own or are authorized to assess this application before scanning it",
    });
  }

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return res.status(400).json({ error: "That doesn't look like a valid URL" });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return res.status(400).json({ error: "Only http:// and https:// URLs are supported" });
  }

  const apiKey = typeof req.body?.apiKey === "string" ? req.body.apiKey.trim() : "";
  const urlProject = apiKey ? await findProjectByApiKeyForScope(apiKey, "scan") : null;
  const billedUserId = req.userId ?? urlProject?.userId;
  const { proceed, usageId } = await reserveOrRespond(billedUserId, urlProject?.id ?? null, "url", res);
  if (!proceed) return;

  try {
    const report = await runUrlScan(parsed.toString());

    let ownerUserId: string | undefined;
    if (urlProject) {
      await recordScan(urlProject.id, report);
      ownerUserId = urlProject.userId;
    }

    res.json(applyScanAccess(report, await planForScan(req, ownerUserId)));
  } catch (err) {
    await releaseScanUsage(usageId);

    if (err instanceof SsrfBlockedError) {
      return res.status(400).json({ error: "That target cannot be scanned: it resolves to a private, reserved, or otherwise disallowed address" });
    }
    if (err instanceof UrlScanUnreachableError) {
      return res.status(422).json({ error: "Couldn't reach that URL", detail: err.message });
    }
    res.status(422).json({ error: "Couldn't scan that URL", detail: (err as Error).message });
  }
}));
