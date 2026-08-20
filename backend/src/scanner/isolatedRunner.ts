/**
 * The single place every route that scans customer-supplied source code
 * (a zip upload or a git repository — NOT a URL scan, see below) goes
 * through, for both the synchronous POST /api/scans* routes and the async
 * job queue (jobs/scanJobs.ts). Selects between two backends via
 * NETTLE_SCANNER_BACKEND:
 *
 *   - "fargate": launches an isolated ECS Fargate task per scan — the
 *     real security boundary described in ISOLATION.md. Set once the
 *     scanner stack (infra/lib/scanner-stack.ts) is actually deployed.
 *   - unset/anything else (default): runs the scan in a worker_thread on
 *     this process (scanner/workerThreadRunner.ts) — real crash/memory
 *     isolation, but explicitly NOT a security boundary, since
 *     worker_threads share this process's OS-level privileges. This is
 *     the only option available anywhere that hasn't deployed the
 *     Fargate stack (every local/dev/CI environment, and this sandbox).
 *
 * URL scans (runUrlScan) are NOT routed through here — they never
 * extract or parse customer-supplied files; they only make SSRF-guarded
 * outbound HTTP requests via ssrfSafeFetch and inspect response headers/
 * TLS, an already-mitigated, materially different threat model. See
 * ISOLATION.md for the full reasoning.
 */
import crypto from "crypto";
import type { ScanReport } from "./types";
import type { ScanWorkerInput } from "./scanWorker";
import type { ScanProgressCallback } from "./index";
import { runViaWorkerThread } from "./workerThreadRunner";
import { launchFargateScan, type FargateScanInput } from "../jobs/fargateScanner";

export type IsolatedScanInput = Extract<ScanWorkerInput, { mode: "upload" | "repo" }>;

export function scannerBackend(): "fargate" | "worker_thread" {
  return process.env.NETTLE_SCANNER_BACKEND === "fargate" ? "fargate" : "worker_thread";
}

export interface RunScanIsolatedOptions {
  onProgress?: ScanProgressCallback;
  timeoutMs?: number;
  /** Reuses an existing job id (from jobs/scanJobs.ts) instead of minting a new one — keeps callback routing keyed by the same id the caller already tracks. */
  jobId?: string;
}

export async function runScanIsolated(input: IsolatedScanInput, options: RunScanIsolatedOptions = {}): Promise<ScanReport> {
  if (scannerBackend() === "fargate") {
    const jobId = options.jobId ?? crypto.randomUUID();
    return launchFargateScan(input as FargateScanInput, jobId);
  }
  return runViaWorkerThread(input, { onProgress: options.onProgress, timeoutMs: options.timeoutMs });
}
