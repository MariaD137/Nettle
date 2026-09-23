import type { Control } from "../types";
import { registerControl } from "../registry";

export const MT_001: Control = {
  controlKey: "MT-001",
  category: "Multi-Tenant Security",
  subcategory: "Tenant isolation",
  name: "Tenant/organization ID not trusted from the client",
  description:
    "A query scoped by a tenant/organization ID that reads that ID from the request body/query/params instead of " +
    "the authenticated session lets the client simply claim to belong to a different tenant — the scoping " +
    "condition meant to isolate one customer's data from another's becomes something the client itself controls.",
  question: "Is the tenant/organization ID used to scope a query derived from the session, not the client's request?",
  defaultSeverity: "critical",
  passCriteria: "No scanned file passes a client-supplied (req.body/req.query/req.params) tenant/organization ID into a database query.",
  failCriteria: "A scanned file passes a client-supplied tenant/organization ID (tenantId, orgId, organizationId) into a database query.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so tenant-scoping was not checked in it.",
  whyItMatters:
    "The entire point of scoping a query by tenant ID is to enforce that a request can only touch its own " +
    "tenant's data — a guarantee that only holds if the tenant ID itself comes from something the request can't " +
    "forge. A session-derived tenant ID (set once, at login, server-side) can't be changed by the client; a " +
    "request-body tenant ID can be edited to any value before the request is sent.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Read the tenant ID from the authenticated session (req.user.tenantId), never from the request body/query/params.",
      developerFix: "Set the tenant ID on the session at login (or derive it from the authenticated user record on each request) and use that value everywhere a query needs tenant scoping. If a client-supplied tenant ID is present anywhere in the request, ignore it, or reject the request if it disagrees with the session's own value.",
      codeExample: "// Instead of: WHERE tenant_id = req.body.tenantId\ndb.query('SELECT * FROM projects WHERE tenant_id = ?', [req.user.tenantId]);",
    },
  ],
  longTermHardening: "Add a test that authenticates as tenant A and requests a resource using tenant B's ID in the request body, asserting the session's own tenant is what's actually used.",
  verificationMethod: "Rescan and confirm the tenant ID used for query scoping now comes from the session, not the client request.",
  references: ["OWASP API Security Top 10: API1:2023 Broken Object Level Authorization"],
  complianceMappings: ["SOC 2 CC6.1"],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const MT_002: Control = {
  controlKey: "MT-002",
  category: "Multi-Tenant Security",
  subcategory: "Object-level authorization",
  name: "Resource lookups scoped by owner/tenant, not just by ID",
  description:
    "A query that looks up a resource by its own ID alone (WHERE id = ?), with no accompanying tenant/owner/user " +
    "condition in the same query, returns that resource to anyone who can guess or enumerate its ID — " +
    "authentication confirms who's asking, but nothing here confirms they're allowed to see this specific record.",
  question: "Do resource lookups by ID also filter by the requesting tenant/owner/user, not just the ID?",
  defaultSeverity: "high",
  passCriteria: "No scanned file queries a resource by a bare ID condition (WHERE id = ?) sourced from req.params.id with no tenant/owner/user condition in the same query.",
  failCriteria: "A scanned file queries a resource by a bare ID condition sourced from req.params.id with no tenant/owner/user condition in the same query.",
  notVerifiedCriteria: "This is a regex-level heuristic over one query statement, not a data-flow or schema analysis — it can't confirm scoping enforced elsewhere (a global ORM scope, a database-level policy, a separate authorization middleware) is absent, only that it isn't visible in the same query text. A FAIL here is worth a manual look, not an automatic conclusion the app is vulnerable.",
  whyItMatters:
    "This is the single most common real-world API vulnerability class (OWASP API Security's #1 for a reason): " +
    "sequential or guessable IDs mean an attacker doesn't need to find anything special, just change the ID in a " +
    "request they're already authorized to make in general, and see whether the response belongs to them or " +
    "someone else's account/tenant.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Add the owner/tenant condition to the query: WHERE id = ? AND tenant_id = ? (or owner_id, depending on the app's model).",
      developerFix: "Every lookup-by-ID that returns a specific record should filter by the requesting user/tenant's own scope in the same query, not check ownership as a separate step after the fact (which is easy to forget on a new endpoint). An ORM-level global scope (applied to every query for that model automatically) removes the risk of a single handler forgetting it.",
      codeExample: "// Instead of: WHERE id = ?\ndb.query('SELECT * FROM projects WHERE id = ? AND tenant_id = ?', [req.params.id, req.user.tenantId]);",
    },
  ],
  longTermHardening: "Add a test that authenticates as one tenant/user and requests another tenant's/user's resource ID directly, asserting a 403/404 rather than the resource itself.",
  verificationMethod: "Rescan and confirm the query now includes a tenant/owner condition, or manually confirm scoping is enforced elsewhere (a global ORM scope, row-level security) if the regex can't see it.",
  references: ["OWASP API Security Top 10: API1:2023 Broken Object Level Authorization"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

registerControl(MT_001);
registerControl(MT_002);
