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
import "./library/browserSecurity";
import "./library/jwtAlgorithm";
import "./library/cryptography";
import "./library/aiSecurity";
import "./library/pathTraversal";
import "./library/transportSecurity";
import "./library/jwtExpiry";
import "./library/cors";
import "./library/cookieSecurity";
import "./library/csrf";
import "./library/inputValidation";
import "./library/requestSize";
import "./library/fileUpload";
import "./library/deserialization";
import "./library/dbCredentials";
import "./library/parameterizedQueries";
import "./library/refreshTokenRotation";
import "./library/sessionStore";
import "./library/sessionExpiration";
import "./library/logoutInvalidation";
import "./library/aiCostLimits";
import "./library/aiToolExecution";
import "./library/aiOutputValidation";
import "./library/dependencyLockfile";
import "./library/legalPolicy";
import "./library/aiContentDisclosure";
import "./library/evalUsage";
import "./library/commandInjection";
import "./library/osvVulnerabilities";
import "./library/codeQuality";
import "./library/frontendSecurity";
import "./library/paymentSecurity";
import "./library/cicdSecurity";
import "./library/multiTenantSecurity";

export { getControl, listControls, listControlsByCategory, getControlLibraryVersion, getControlVersionsSnapshot } from "./registry";
export { hydrateCheckResult, hydrateCheckResults, type HydratedFinding } from "./hydrate";
export { computeReleaseImpact } from "./releaseGate";
export type { Control, Recommendation, ReleaseImpact, TechnologyFix } from "./types";
