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
import { requireAuth } from "../auth/middleware";

export const scansRouter = Router();

const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB — plenty for source code, not for asset-heavy repos
});

scansRouter.post("/api/scans", upload.single("codebase"), (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: "Upload a zip file under the 'codebase' field" });
  }
  if (path.extname(req.file.originalname).toLowerCase() !== ".zip") {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "Only .zip uploads are supported right now" });
  }

  const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-scan-"));
  try {
    execFileSync("unzip", ["-q", "-o", req.file.path, "-d", extractDir]);
    const scanRoot = resolveScanRoot(extractDir);
    const report = runScan(scanRoot);

    // Optional: if the request identifies a project (same API key the
    // monitoring middleware uses), persist the scan against it so the badge
    // and dashboard have real history. Scanning without a project is still
    // fully supported — a quick one-off check needs no account at all.
    const apiKey = req.header("x-nettle-api-key");
    if (apiKey) {
      const project = findProjectByApiKey(apiKey);
      if (project) recordScan(project.id, report);
    }

    res.json(report);
  } catch (err) {
    res.status(422).json({ error: "Couldn't extract or scan the uploaded file", detail: (err as Error).message });
  } finally {
    fs.unlinkSync(req.file.path);
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
});

const ALLOWED_HOSTS = ["github.com", "gitlab.com", "bitbucket.org"];
const REPO_URL_PATTERN = /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[\w.\-]+\/[\w.\-]+(\.git)?$/;

scansRouter.post("/api/scans/repo", requireAuth, (req: Request, res: Response) => {
  const repoUrl = typeof req.body?.repoUrl === "string" ? req.body.repoUrl.trim() : "";
  const branch = typeof req.body?.branch === "string" ? req.body.branch.trim() : "";
  const apiKey = typeof req.body?.apiKey === "string" ? req.body.apiKey.trim() : "";

  if (!repoUrl) {
    return res.status(400).json({ error: "Provide a 'repoUrl' (e.g. https://github.com/owner/repo)" });
  }
  if (!REPO_URL_PATTERN.test(repoUrl)) {
    return res.status(400).json({ error: "Only public GitHub, GitLab, and Bitbucket HTTPS URLs are supported" });
  }

  const cloneDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-repo-"));
  try {
    const args = ["clone", "--depth", "1"];
    if (branch) args.push("--branch", branch);
    args.push(repoUrl, cloneDir);

    execFileSync("git", args, { timeout: 60_000, stdio: "pipe" });

    const report = runScan(cloneDir);

    if (apiKey) {
      const project = findProjectByApiKey(apiKey);
      if (project) recordScan(project.id, report);
    }

    res.json(report);
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
