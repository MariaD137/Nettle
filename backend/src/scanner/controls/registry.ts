import crypto from "crypto";
import type { Control } from "./types";

/**
 * The control library: a single in-memory registry of every Control
 * definition, keyed by controlKey. Library modules under ./library register
 * their controls at import time (see ./index.ts); nothing else should
 * construct a Control ad hoc inline in a scanner module.
 */
const registry = new Map<string, Control>();

export function registerControl(control: Control): void {
  if (registry.has(control.controlKey)) {
    throw new Error(`Control ${control.controlKey} is already registered — controlKey must be unique`);
  }
  registry.set(control.controlKey, control);
}

export function getControl(controlKey: string): Control | undefined {
  return registry.get(controlKey);
}

export function listControls(): Control[] {
  return Array.from(registry.values());
}

export function listControlsByCategory(category: string): Control[] {
  return listControls().filter((c) => c.category === category);
}

/** Test-only: clears the registry so test files don't leak controls into each other. */
export function __resetRegistryForTests(): void {
  registry.clear();
}

/**
 * A deterministic fingerprint of the whole control library's version state —
 * every registered controlKey paired with its own `version`, sorted so
 * registration order never changes the result. Two scans with the same value
 * here were evaluated against exactly the same set of control definitions;
 * a different value means at least one control's criteria, or the set of
 * controls itself, changed between them — see scanComparison.ts, which uses
 * this (via each scan's stored controlVersions snapshot, not a live registry
 * read) to avoid claiming a finding was "fixed" when it may simply no longer
 * be checked the same way.
 */
export function getControlLibraryVersion(): string {
  const parts = listControls()
    .map((c) => `${c.controlKey}@${c.version}`)
    .sort();
  return crypto.createHash("sha256").update(parts.join(",")).digest("hex").slice(0, 16);
}

/** controlKey -> version, for every currently-registered control. Snapshotted onto ScanReport at scan time. */
export function getControlVersionsSnapshot(): Record<string, string> {
  const snapshot: Record<string, string> = {};
  for (const c of listControls()) snapshot[c.controlKey] = c.version;
  return snapshot;
}
