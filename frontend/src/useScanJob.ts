import { useEffect, useRef, useState } from "react";
import { api, ApiError, type ScanJob, type ScanReport } from "./api";

const POLL_INTERVAL_MS = 700;

interface UseScanJobResult {
  job: ScanJob | null;
  scanning: boolean;
  error: string | null;
  startUpload: (file: File, apiKey?: string) => Promise<ScanReport | null>;
  startRepo: (repoUrl: string, opts?: { branch?: string; apiKey?: string }) => Promise<ScanReport | null>;
  cancel: () => void;
}

/**
 * Drives a scan job through submit -> poll -> resolve, backing the
 * real-time step-by-step progress UI in ScanTab and the onboarding scan
 * step. Both call sites need the same shape (start it, watch job.steps
 * update live, cancel, get the report back at the end), so this is shared
 * rather than duplicated.
 */
export function useScanJob(): UseScanJobResult {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollHandle = useRef<number | null>(null);
  const jobIdRef = useRef<string | null>(null);

  useEffect(() => {
    return () => {
      if (pollHandle.current !== null) window.clearInterval(pollHandle.current);
    };
  }, []);

  function stopPolling() {
    if (pollHandle.current !== null) {
      window.clearInterval(pollHandle.current);
      pollHandle.current = null;
    }
  }

  function watch(jobId: string): Promise<ScanReport | null> {
    jobIdRef.current = jobId;
    return new Promise((resolve) => {
      pollHandle.current = window.setInterval(async () => {
        try {
          const current = await api.getScanJob(jobId);
          setJob(current);
          if (current.status === "completed") {
            stopPolling();
            setScanning(false);
            resolve(current.report);
          } else if (current.status === "failed") {
            stopPolling();
            setScanning(false);
            setError(current.friendlyError || current.error || "Scan failed");
            resolve(null);
          } else if (current.status === "cancelled") {
            stopPolling();
            setScanning(false);
            resolve(null);
          }
        } catch (err) {
          stopPolling();
          setScanning(false);
          setError(err instanceof ApiError ? err.message : "Lost track of the scan's progress");
          resolve(null);
        }
      }, POLL_INTERVAL_MS);
    });
  }

  async function startUpload(file: File, apiKey?: string): Promise<ScanReport | null> {
    setError(null);
    setJob(null);
    setScanning(true);
    try {
      const { jobId } = await api.startUploadScanJob(file, apiKey);
      return await watch(jobId);
    } catch (err) {
      setScanning(false);
      setError(err instanceof ApiError ? err.message : "Couldn't start the scan");
      return null;
    }
  }

  async function startRepo(repoUrl: string, opts?: { branch?: string; apiKey?: string }): Promise<ScanReport | null> {
    setError(null);
    setJob(null);
    setScanning(true);
    try {
      const { jobId } = await api.startRepoScanJob(repoUrl, opts);
      return await watch(jobId);
    } catch (err) {
      setScanning(false);
      setError(err instanceof ApiError ? err.message : "Couldn't start the scan");
      return null;
    }
  }

  function cancel() {
    stopPolling();
    setScanning(false);
    setError("Scan cancelled.");
    if (jobIdRef.current) {
      api.cancelScanJob(jobIdRef.current).catch(() => {
        // Best-effort — if the cancel request itself fails, the UI has
        // already stopped waiting either way.
      });
    }
  }

  return { job, scanning, error, startUpload, startRepo, cancel };
}
