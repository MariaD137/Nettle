/**
 * The control library. Importing this module registers every control it
 * knows about (each library/*.ts file calls registerControl() at import
 * time) — import this module (not an individual library file) wherever the
 * registry needs to be populated, e.g. scanner/index.ts.
 */
import "./library/auth";
import "./library/secrets";
import "./library/api";
import "./library/database";

export { getControl, listControls, listControlsByCategory } from "./registry";
export { hydrateCheckResult, hydrateCheckResults, type HydratedFinding } from "./hydrate";
export { computeReleaseImpact } from "./releaseGate";
export type { Control, Recommendation, ReleaseImpact, TechnologyFix } from "./types";
