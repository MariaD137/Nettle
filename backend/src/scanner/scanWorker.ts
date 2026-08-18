/**
 * The scan-job worker_thread entry point. Runs off the main thread so a
 * long, synchronous scan (Semgrep, a git clone — both use execFileSync,
 * which blocks whatever thread it runs on) doesn't block the server's
 * event loop and every other request with it. See jobs/scanJobs.ts for how
 * this is spawned and messaged.
 *
 * Deliberately has no knowledge of HTTP, auth, quotas, or billing — it
 * only knows how to turn one of three job inputs into a ScanReport and
 * report progress along the way. Everything else is the job manager's job.
 */
import { parentPort, workerData } from "worker_threads";
import fs from "fs";
import os from "os";
import path from "path";
import { runScan, runUrlScan, type ScanStepEvent } from "./index";
import { safeExtractZip } from "./safeExtraction";
import { resolveScanRoot } from "./resolveScanRoot";
import { cloneRepo } from "./gitAuth";

export type ScanWorkerInput =
  | { mode: "upload"; zipPath: string }
  | { mode: "repo"; repoUrl: string; branch: string; token: string | null }
  | { mode: "url"; targetUrl: string };

export type ScanWorkerMessage =
  | { type: "progress"; event: ScanStepEvent }
  | { type: "done"; report: import("./types").ScanReport }
  | { type: "error"; message: string };

function post(message: ScanWorkerMessage) {
  parentPort!.postMessage(message);
}

async function main() {
  const input = workerData as ScanWorkerInput;
  const onProgress = (event: ScanStepEvent) => post({ type: "progress", event });

  try {
    if (input.mode === "upload") {
      const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-job-upload-"));
      try {
        safeExtractZip(input.zipPath, extractDir);
        const scanRoot = resolveScanRoot(extractDir);
        const report = runScan(scanRoot, "SOURCE", onProgress);
        post({ type: "done", report });
      } finally {
        fs.rmSync(extractDir, { recursive: true, force: true });
        fs.rmSync(input.zipPath, { force: true });
      }
    } else if (input.mode === "repo") {
      const cloneDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-job-repo-"));
      try {
        cloneRepo(input.repoUrl, input.branch, cloneDir, input.token);
        const report = runScan(cloneDir, "GITHUB", onProgress);
        post({ type: "done", report });
      } finally {
        fs.rmSync(cloneDir, { recursive: true, force: true });
      }
    } else {
      const report = await runUrlScan(input.targetUrl, onProgress);
      post({ type: "done", report });
    }
  } catch (err) {
    post({ type: "error", message: (err as Error).message || String(err) });
  }
}

main();
