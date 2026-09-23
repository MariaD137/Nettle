import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const TENANT_QUERY_CALL = /\.(query|find|findOne|findById)\s*\([^;]*?\b(tenantId|orgId|organizationId|tenant_id|org_id)\b[^;]*?\)/gis;
const CLIENT_SOURCED_TENANT_ID = /\breq\.(body|query|params)\.(tenantId|orgId|organizationId|tenant_id|org_id)\b/i;

const ID_LOOKUP_QUERY_CALL = /\.query\s*\([^;]*?req\.params\.id\b[^;]*?\)/gis;
const SCOPING_TERM = /\b(tenant|org|owner|organization|user)_?id\b/i;

/**
 * MT-001/002, wired to the control library. Third Phase B category (master
 * spec §20) — entirely new, no legacy module to migrate from. Confirmed via
 * grep before writing anything that no existing control covers tenant
 * scoping or object-level authorization; AUTH-001 only checks that SOME
 * authentication check exists on a route, not that a specific resource
 * lookup is scoped to its owner/tenant.
 *
 * Both checks are gated on their own applicability, matching the pattern
 * established for the other Phase B categories: MT-001 only produces a
 * result when the scanned source shows some tenant-scoped query pattern at
 * all (client-sourced or session-sourced); MT-002 only produces a result
 * when a query looks up a resource by req.params.id at all. An app with
 * neither pattern gets no result, not an unearned PASS.
 *
 * MT-002's confidence is deliberately lower (55, not 80-90 like most
 * regex-based FAILs elsewhere in this library) -- it's a single-query-text
 * heuristic that can't see scoping enforced elsewhere (a global ORM scope,
 * a database row-level-security policy), so a FAIL here is honestly
 * flagged as worth a manual look, not a confirmed vulnerability. See the
 * control's own notVerifiedCriteria for the same point made to the user.
 */
export function scanMultiTenantSecurityControl(files: string[], targetRoot: string): CheckResult[] {
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let anyUnreadable = false;
  const results: CheckResult[] = [];

  let hasTenantQuery = false;
  let tenantFailed = false;
  let hasIdLookupQuery = false;
  let idLookupFailed = false;

  for (const file of jsFiles) {
    const rel = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      anyUnreadable = true;
      continue;
    }

    TENANT_QUERY_CALL.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = TENANT_QUERY_CALL.exec(text))) {
      hasTenantQuery = true;
      if (CLIENT_SOURCED_TENANT_ID.test(match[0])) {
        tenantFailed = true;
        results.push({
          checkId: generateCheckId("Multi-Tenant Security", "MT-001:fail", `${rel}:${match.index}`),
          status: "FAIL",
          category: "Multi-Tenant Security",
          title: "Tenant/organization ID taken directly from the client request",
          detail: "A query is scoped by a tenant/organization ID read from req.body/req.query/req.params instead of the authenticated session.",
          severity: "critical",
          file: rel,
          confidence: 80,
          detectionMethod: "regex",
          remediation: "Read the tenant ID from the authenticated session (req.user.tenantId), never from the request body/query/params.",
          controlKey: "MT-001",
        });
      }
    }

    ID_LOOKUP_QUERY_CALL.lastIndex = 0;
    while ((match = ID_LOOKUP_QUERY_CALL.exec(text))) {
      hasIdLookupQuery = true;
      if (!SCOPING_TERM.test(match[0])) {
        idLookupFailed = true;
        results.push({
          checkId: generateCheckId("Multi-Tenant Security", "MT-002:fail", `${rel}:${match.index}`),
          status: "FAIL",
          category: "Multi-Tenant Security",
          title: "Resource looked up by ID with no visible tenant/owner scoping",
          detail: "A query looks up a resource by req.params.id with no tenant/owner/user condition in the same query — anyone who can guess or enumerate the ID can request the record, if nothing else in the request path enforces ownership.",
          severity: "high",
          file: rel,
          confidence: 55,
          detectionMethod: "regex",
          remediation: "Add the owner/tenant condition to the query: WHERE id = ? AND tenant_id = ? (or owner_id, depending on the app's model).",
          controlKey: "MT-002",
        });
      }
    }
  }

  if (hasTenantQuery && !tenantFailed) {
    results.push(anyUnreadable ? notVerified("MT-001", "tenant-scoping") : pass("MT-001", "Tenant/organization ID is not taken directly from the client request"));
  }

  if (hasIdLookupQuery && !idLookupFailed) {
    // PASS confidence (80) is deliberately higher than MT-002's own FAIL
    // confidence (55): seeing a scoping term present is more reliable
    // evidence than its absence in a narrow single-query-text window —
    // the same "weak evidence" asymmetry DB-003 uses.
    results.push(anyUnreadable ? notVerified("MT-002", "object-level authorization") : pass("MT-002", "Resource lookups by ID include tenant/owner scoping"));
  }

  return results;
}

function pass(controlKey: string, title: string): CheckResult {
  return {
    checkId: generateCheckId("Multi-Tenant Security", `${controlKey}:pass`),
    status: "PASS",
    category: "Multi-Tenant Security",
    title,
    confidence: 80,
    detectionMethod: "regex",
    controlKey,
  };
}

function notVerified(controlKey: string, what: string): CheckResult {
  return {
    checkId: generateCheckId("Multi-Tenant Security", `${controlKey}:unreadable`),
    status: "NOT_VERIFIED",
    category: "Multi-Tenant Security",
    title: `Some files could not be read for ${what} analysis`,
    confidence: 0,
    detectionMethod: "regex",
    controlKey,
  };
}
