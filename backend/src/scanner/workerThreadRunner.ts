/**
 * One-shot, Promise-based wrapper around spawning scanWorker.ts for a
 * single scan and waiting for its result — used by isolatedRunner.ts's
 * worker_thread backend for the synchronous POST /api/scans* routes
 * (which, unlike the async job queue in jobs/scanJobs.ts, previously ran
 * safeExtractZip/cloneRepo/runScan directly in-process with no thread
 * boundary at all). jobs/scanJobs.ts keeps its own, separate worker-thread
 * spawning logic (it needs per-job step tracking and queue/concurrency
 * bookkeeping this helper deliberately doesn't have) — this is not a
 * refactor of that, just the same underlying pattern reused for a
 * simpler, single-request case.
 *
 * Explicitly NOT the security boundary described in ISOLATION.md —
 * worker_threads share the host process's OS-level privileges. This
 * exists so a deployment without the Fargate stack configured still gets
 * a real thread boundary (crash isolation, a real memory ceiling) instead
 * of the previous fully-inline execution, while the isolatedRunner
 * default stays honest about what it is and isn't.
 */
import { Worker } from "worker_threads";
import path from "path";
import type { ScanReport } from "./types";
import type { ScanWorkerInput, ScanWorkerMessage } from "./scanWorker";
import type { ScanProgressCallback } from "./index";

function workerEntry(): { file: string; execArgv: string[] } {
  const scannerDir = __dirname;
  const compiled = __filename.endsWith(".js");
  return compiled
    ? { file: path.join(scannerDir, "scanWorker.js"), execArgv: [] }
    : { file: path.join(scannerDir, "scanWorker.ts"), execArgv: ["--require", "tsx/cjs"] };
}

function workerMemoryLimitMb(): number {
  const raw = process.env.NETTLE_SCAN_WORKER_MAX_MEMORY_MB;
  const n = raw ? parseInt(raw, 10) : 512;
  return Number.isFinite(n) && n > 0 ? n : 512;
}

export interface WorkerThreadRunOptions {
  onProgress?: ScanProgressCallback;
  timeoutMs?: number; // default 10 minutes, same ceiling jobs/scanJobs.ts uses
}

export function runViaWorkerThread(input: ScanWorkerInput, options: WorkerThreadRunOptions = {}): Promise<ScanReport> {
  const timeoutMs = options.timeoutMs ?? 10 * 60 * 1000;

  return new Promise<ScanReport>((resolve, reject) => {
    const { file, execArgv } = workerEntry();
    const memoryLimitMb = workerMemoryLimitMb();
    const worker = new Worker(file, {
      execArgv,
      workerData: input,
      resourceLimits: { maxOldGenerationSizeMb: memoryLimitMb, maxYoungGenerationSizeMb: Math.min(64, memoryLimitMb) },
    });

    let settled = false;
    const timeoutHandle = setTimeout(() => {
      if (settled) return;
      settled = true;
      worker.terminate();
      reject(new Error(`Scan timed out after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);
    timeoutHandle.unref();

    function finish(fn: () => void) {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutHandle);
      worker.removeAllListeners();
      fn();
    }

    worker.on("message", (message: ScanWorkerMessage) => {
      if (message.type === "progress") {
        options.onProgress?.(message.event);
      } else if (message.type === "done") {
        finish(() => resolve(message.report));
      } else if (message.type === "error") {
        finish(() => reject(new Error(message.message)));
      }
      // "tmpdir" messages are informational only here — this helper has no
      // caller-visible job record to attach a fallback-cleanup path to,
      // and the worker's own finally block (scanWorker.ts) already cleans
      // up on every exit path except a hard terminate(), which only this
      // helper's own timeout above triggers.
    });

    worker.on("error", (err) => {
      finish(() => reject(err));
    });

    worker.on("exit", (code) => {
      finish(() => reject(new Error(`Scan worker exited unexpectedly (code ${code})`)));
    });
  });
}
