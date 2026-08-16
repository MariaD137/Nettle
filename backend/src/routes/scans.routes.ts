import { Router, type Request, type Response } from "express";
import { execFileSync, execFile } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import multer from "multer";
import { runScan } from "../scanner";
import { resolveScanRoot } from "../scanner/resolveScanRoot";
import { findProjectByApiKey } from "../patrol/projects";
import { recordScan } from "../patrol/scans";
import { requireAuth, optionalAuth } from "../auth/middleware";
import { requireSubscription } from "../billing/subscription";
import { getUserById } from "../auth/users";
import { applyScanAccess } from "../billing/scanAccess";
import { getQuotaState, recordScanUsage } from "../billing/scanQuota";
import { safeExtractZip } from "../scanner/safeExtraction";
import type { Request as ExpressRequest } from "express";

export const scansRouter = Router();

/**
 * Refuses the scan when the billing account has used its monthly allowance.
 * Returns true when the caller should stop. Anonymous, unauthenticated scans
 * have no account to meter and are preview-only, so they pass through.
 */
function quotaExceeded(userId: string | undefined, res: Response): boolean {
  if (!userId) return false;
  const quota = getQuotaState(userId);
  if (!quota || !quota.exhausted) return false;

  res.status(402).json({
    error: `You have used all ${quota.limit} scans in this billing period. Your allowance resets on ${new Date(quota.periodEnd).toLocaleDateString("en-GB")}.`,
    quotaExceeded: true,
    limit: quota.limit,
    used: quota.used,
    remaining: 0,
    periodEnd: quota.periodEnd,
  });
  return true;
}

/**
 * Which plan governs this scan's report. A bearer token wins; failing that,
 * an API key identifies the owning project, and that project owner's plan
 * applies — so CI runs authenticated only by a project key still get the
 * full report the account pays for.
 */
function planForScan(req: ExpressRequest, apiKeyProjectUserId?: string): string {
  if (req.userPlan) return req.userPlan;
  if (apiKeyProjectUserId) {
    const owner = getUserById(apiKeyProjectUserId);
    if (owner) return owner.plan;
  }
  return "free";
}

const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB — plenty for source code, not for asset-heavy repos
});

scansRouter.post("/api/scans", optionalAuth, upload.single("codebase"), (req: Request, res: Response) => {
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
  const upfrontProject = upfrontKey ? findProjectByApiKey(upfrontKey) : null;
  const billedUserId = req.userId ?? upfrontProject?.userId;
  if (quotaExceeded(billedUserId, res)) {
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
      recordScan(upfrontProject.id, report);
      ownerUserId = upfrontProject.userId;
    }

    if (billedUserId) recordScanUsage(billedUserId, upfrontProject?.id ?? null, "upload");

    res.json(applyScanAccess(report, planForScan(req, ownerUserId)));
  } catch (err) {
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
    fs.unlinkSync(req.file.path);
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
});

const ALLOWED_HOSTS = ["github.com", "gitlab.com", "bitbucket.org"];
const REPO_URL_PATTERN = /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.\-]+\/[\w.\-]+(\.git)?$/;

scansRouter.post("/api/scans/repo", requireAuth, requireSubscription, (req: Request, res: Response) => {
  const repoUrl = typeof req.body?.repoUrl === "string" ? req.body.repoUrl.trim() : "";
  const branch = typeof req.body?.branch === "string" ? req.body.branch.trim() : "";
  const apiKey = typeof req.body?.apiKey === "string" ? req.body.apiKey.trim() : "";

  if (!repoUrl) {
    return res.status(400).json({ error: "Provide a 'repoUrl' (e.g. https://github.com/owner/repo)" });
  }
  if (!REPO_URL_PATTERN.test(repoUrl)) {
    return res.status(400).json({ error: "Only public GitHub, GitLab, and Bitbucket HTTPS URLs are supported" });
  }

  const repoProject = apiKey ? findProjectByApiKey(apiKey) : null;
  const billedUserId = req.userId ?? repoProject?.userId;
  if (quotaExceeded(billedUserId, res)) return;

  const cloneDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-repo-"));
  try {
    const args = ["clone", "--depth", "1"];
    if (branch) args.push("--branch", branch);
    args.push(repoUrl, cloneDir);

    execFileSync("git", args, { timeout: 60_000, stdio: "pipe" });

    const report = runScan(cloneDir);

    let ownerUserId: string | undefined;
    if (repoProject) {
      recordScan(repoProject.id, report);
      ownerUserId = repoProject.userId;
    }

    if (billedUserId) recordScanUsage(billedUserId, repoProject?.id ?? null, "repo");

    res.json(applyScanAccess(report, planForScan(req, ownerUserId)));
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
