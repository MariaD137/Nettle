import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

/**
 * Static analysis over Dockerfile text. Checks are line/instruction based —
 * this can't evaluate build-arg values passed in at build time, or follow
 * a multi-stage build's final effective USER across stages perfectly, so
 * findings describe what the Dockerfile text says, not the built image.
 */

// `_` doesn't break a \b word boundary, so a plain \b pattern would miss the
// most common real naming style (STRIPE_SECRET_KEY, DB_PASSWORD, ...). Treat
// underscore and string start/end as delimiters instead.
const SECRET_LIKE_NAME = /(?:^|_)(API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY|ACCESS_KEY|AWS_SECRET|CREDENTIAL)(?:_|$)/i;
const LOOKS_LIKE_LITERAL_VALUE = /^[^$][\w\-./+=]{6,}$/; // not empty, not starting with $ (a var reference)

function isDockerfile(filename: string): boolean {
  return filename.toLowerCase().includes("dockerfile");
}

export function scanDockerSecurity(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const dockerfiles = files.filter((f) => isDockerfile(path.basename(f)));
  if (dockerfiles.length === 0) return { findings, passed: [] };

  let anyMissingUser = false;
  let anySecretInEnvArg = false;
  let anyUnpinnedBase = false;
  let anyMissingHealthcheck = false;

  for (const file of dockerfiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);
    const lines = text.split("\n");

    if (!/^\s*USER\s+\S+/im.test(text)) {
      anyMissingUser = true;
      findings.push({
        severity: "medium",
        category: "Infrastructure",
        title: "Dockerfile has no USER instruction — container runs as root",
        detail: "No USER instruction was found, so the container's default process runs as root inside the container. A container-breakout vulnerability is more dangerous when the compromised process already has root inside its namespace.",
        file: rel,
        line: null,
        remediation: "Add a non-root user and switch to it: `RUN useradd -m appuser` then `USER appuser` before the final CMD/ENTRYPOINT.",
      });
    }

    // Multi-stage builds reference earlier stages by name (`FROM builder AS
    // runtime`) — those aren't registry images and shouldn't be flagged for
    // missing a version pin. Collect stage names up front.
    const stageNames = new Set<string>();
    for (const line of lines) {
      const asMatch = line.match(/^\s*FROM\s+\S+\s+AS\s+(\S+)/i);
      if (asMatch) stageNames.add(asMatch[1].toLowerCase());
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const envOrArgMatch = line.match(/^\s*(ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=?\s*(.*)$/);
      if (envOrArgMatch) {
        const [, , name, rawValue] = envOrArgMatch;
        const value = rawValue.trim().replace(/^["']|["']$/g, "");
        if (SECRET_LIKE_NAME.test(name) && value && LOOKS_LIKE_LITERAL_VALUE.test(value)) {
          anySecretInEnvArg = true;
          findings.push({
            severity: "critical",
            category: "Infrastructure",
            title: `Hardcoded credential in Dockerfile ${envOrArgMatch[1]} instruction`,
            detail: `"${name}" looks like a secret and is assigned a literal value directly in the Dockerfile. Anything baked into an image layer is recoverable from the image even if removed in a later layer.`,
            file: rel,
            line: i + 1,
            remediation: "Pass secrets at runtime (e.g. mounted secret files, an orchestrator's secret store, or --secret with BuildKit) instead of ARG/ENV with a literal value.",
          });
        }
      }

      const fromMatch = line.match(/^\s*FROM\s+([^\s]+)(?:\s+AS\s+\S+)?/i);
      if (fromMatch) {
        const image = fromMatch[1];
        const isLocalStageRef = stageNames.has(image.toLowerCase());
        const hasDigest = image.includes("@sha256:");
        const hasExplicitNonLatestTag = /:[^:@]+$/.test(image) && !image.endsWith(":latest");
        if (!isLocalStageRef && !hasDigest && !hasExplicitNonLatestTag) {
          anyUnpinnedBase = true;
          findings.push({
            severity: "low",
            category: "Infrastructure",
            title: "Base image is not pinned to a specific version",
            detail: `"${image}" has no tag (defaults to :latest) or is explicitly tagged :latest. An unpinned base image can change contents between builds without notice.`,
            file: rel,
            line: i + 1,
            remediation: "Pin to a specific version tag or, ideally, a content digest: `FROM node:20.11.1@sha256:...`.",
          });
        }
      }
    }

    if (!/^\s*HEALTHCHECK\b/im.test(text)) {
      anyMissingHealthcheck = true;
      findings.push({
        severity: "low",
        category: "Infrastructure",
        title: "Dockerfile has no HEALTHCHECK instruction",
        detail: "Without a HEALTHCHECK, an orchestrator can only tell if the process exited, not whether it's actually serving traffic correctly.",
        file: rel,
        line: null,
        remediation: "Add a HEALTHCHECK instruction, or configure liveness/readiness probes at the orchestrator level (e.g. Kubernetes) if that's where health is actually checked.",
      });
    }
  }

  const passed: Pass[] = [];
  if (!anyMissingUser) passed.push({ category: "Infrastructure", title: "Dockerfile(s) specify a non-root USER" });
  if (!anySecretInEnvArg) passed.push({ category: "Infrastructure", title: "No hardcoded credentials found in Dockerfile ENV/ARG instructions" });
  if (!anyUnpinnedBase) passed.push({ category: "Infrastructure", title: "Base image(s) are pinned to a specific version or digest" });
  if (!anyMissingHealthcheck) passed.push({ category: "Infrastructure", title: "Dockerfile(s) define a HEALTHCHECK" });

  return { findings, passed };
}
