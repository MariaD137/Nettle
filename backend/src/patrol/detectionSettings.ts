import { db } from "../db";

export interface DetectionSettings {
  projectId: string;
  bruteForceThreshold: number;
  highRequestRateThreshold: number;
  credentialStuffingMinIps: number;
  updatedAt: string | null;
}

// The values detection.ts used as hardcoded constants before this table
// existed — kept here as the single source of truth for "default", so a
// project with no override row behaves exactly as it always did.
export const DEFAULT_DETECTION_SETTINGS: Omit<DetectionSettings, "projectId" | "updatedAt"> = {
  bruteForceThreshold: 5,
  highRequestRateThreshold: 50,
  credentialStuffingMinIps: 5,
};

interface DetectionSettingsRow {
  project_id: string;
  brute_force_threshold: number;
  high_request_rate_threshold: number;
  credential_stuffing_min_ips: number;
  updated_at: string;
}

function toSettings(row: DetectionSettingsRow): DetectionSettings {
  return {
    projectId: row.project_id,
    bruteForceThreshold: row.brute_force_threshold,
    highRequestRateThreshold: row.high_request_rate_threshold,
    credentialStuffingMinIps: row.credential_stuffing_min_ips,
    updatedAt: row.updated_at,
  };
}

/** Always returns a usable settings object — defaults when no override exists. */
export function getDetectionSettings(projectId: string): DetectionSettings {
  const row = db.prepare("SELECT * FROM detection_settings WHERE project_id = ?").get(projectId) as
    | DetectionSettingsRow
    | undefined;
  if (row) return toSettings(row);
  return { projectId, ...DEFAULT_DETECTION_SETTINGS, updatedAt: null };
}

function clampThreshold(value: unknown, fallback: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.round(n);
}

/**
 * Upserts an override row. Any field omitted keeps its current value (or
 * the default, if this project has never customized anything before).
 */
export function updateDetectionSettings(
  projectId: string,
  updates: { bruteForceThreshold?: unknown; highRequestRateThreshold?: unknown; credentialStuffingMinIps?: unknown }
): DetectionSettings {
  const current = getDetectionSettings(projectId);
  const bruteForceThreshold = updates.bruteForceThreshold !== undefined ? clampThreshold(updates.bruteForceThreshold, current.bruteForceThreshold) : current.bruteForceThreshold;
  const highRequestRateThreshold = updates.highRequestRateThreshold !== undefined ? clampThreshold(updates.highRequestRateThreshold, current.highRequestRateThreshold) : current.highRequestRateThreshold;
  const credentialStuffingMinIps = updates.credentialStuffingMinIps !== undefined ? clampThreshold(updates.credentialStuffingMinIps, current.credentialStuffingMinIps) : current.credentialStuffingMinIps;
  const updatedAt = new Date().toISOString();

  const existing = db.prepare("SELECT 1 FROM detection_settings WHERE project_id = ?").get(projectId);
  if (existing) {
    db.prepare(
      "UPDATE detection_settings SET brute_force_threshold = ?, high_request_rate_threshold = ?, credential_stuffing_min_ips = ?, updated_at = ? WHERE project_id = ?"
    ).run(bruteForceThreshold, highRequestRateThreshold, credentialStuffingMinIps, updatedAt, projectId);
  } else {
    db.prepare(
      "INSERT INTO detection_settings (project_id, brute_force_threshold, high_request_rate_threshold, credential_stuffing_min_ips, updated_at) VALUES (?, ?, ?, ?, ?)"
    ).run(projectId, bruteForceThreshold, highRequestRateThreshold, credentialStuffingMinIps, updatedAt);
  }

  return getDetectionSettings(projectId);
}

/** Restores a project to the built-in defaults by removing its override row. */
export function resetDetectionSettings(projectId: string): DetectionSettings {
  db.prepare("DELETE FROM detection_settings WHERE project_id = ?").run(projectId);
  return getDetectionSettings(projectId);
}
