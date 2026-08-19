import { getProject } from "./projects";
import type { Project } from "./types";

/**
 * THE single authoritative project-ownership check. Every route that
 * scopes a resource to a project must verify ownership through this
 * function rather than re-deriving its own "does this user own this
 * project" query — that exact check had drifted into four separately
 * maintained copies (projects.routes.ts, customRules.routes.ts,
 * analytics.routes.ts, and seven copy-pasted-inline instances in
 * integrations.routes.ts) before this. No behavior changed by
 * introducing this — each call site still decides its own response
 * (some 404 either way to avoid an existence leak, one 403s once
 * authentication is already established) — only the ownership decision
 * itself is now made in one place.
 *
 * Returns the project when userId genuinely owns projectId, null
 * otherwise (missing project, wrong owner, or no userId at all).
 */
export function getOwnedProject(projectId: string | null | undefined, userId: string | null | undefined): Project | null {
  if (!projectId || !userId) return null;
  const project = getProject(projectId);
  if (!project || project.userId !== userId) return null;
  return project;
}
