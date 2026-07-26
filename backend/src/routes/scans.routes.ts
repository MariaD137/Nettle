import { Router, type Request, type Response } from "express";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import multer from "multer";
import { runScan } from "../scanner";
import { resolveScanRoot } from "../scanner/resolveScanRoot";

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
    res.json(report);
  } catch (err) {
    res.status(422).json({ error: "Couldn't extract or scan the uploaded file", detail: (err as Error).message });
  } finally {
    fs.unlinkSync(req.file.path);
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
});
