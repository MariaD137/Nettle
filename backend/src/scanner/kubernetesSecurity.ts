import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

/**
 * Static analysis over Kubernetes YAML manifests. A file only gets treated
 * as a k8s manifest if it actually has `apiVersion:` and `kind:` — .yaml
 * files are also used for CI configs, docker-compose, and app config, and
 * treating all of them as k8s would produce false positives.
 *
 * Manifests are split into YAML documents on `---` and matched with a
 * simple regex/indentation approach rather than a real YAML parser, so
 * deeply nested or unusually formatted manifests can be missed.
 */

const PRIVILEGED_CONTAINER = /privileged\s*:\s*true/i;
const HOST_NETWORK = /hostNetwork\s*:\s*true/i;
const HOST_PATH_VOLUME = /hostPath\s*:/i;
const DANGEROUS_CAPS = /add\s*:\s*\[[^\]]*\b(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE)\b[^\]]*\]/i;
const DANGEROUS_CAPS_LIST_ITEM = /-\s*(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE)\s*$/im;
const RUN_AS_NON_ROOT_FALSE = /runAsNonRoot\s*:\s*false/i;
const WILDCARD_RBAC = /apiGroups\s*:\s*\[\s*["']?\*["']?\s*\][\s\S]{0,200}?resources\s*:\s*\[\s*["']?\*["']?\s*\][\s\S]{0,200}?verbs\s*:\s*\[\s*["']?\*["']?\s*\]/i;
const NODEPORT_OR_LB = /type\s*:\s*(NodePort|LoadBalancer)/i;
const SECRET_ENV_LITERAL = /-\s*name\s*:\s*\S*(PASSWORD|SECRET|TOKEN|KEY)\S*\s*\n\s*value\s*:\s*["']?\S+/i;
const RESOURCE_LIMITS = /resources\s*:[\s\S]{0,300}?limits\s*:/i;
const HAS_CONTAINERS = /containers\s*:/i;

function looksLikeK8sManifest(text: string): boolean {
  return /^\s*apiVersion\s*:/m.test(text) && /^\s*kind\s*:/m.test(text);
}

function getKind(doc: string): string | null {
  const m = doc.match(/^\s*kind\s*:\s*(\S+)/m);
  return m ? m[1] : null;
}

export function scanKubernetesSecurity(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const yamlFiles = files.filter((f) => /\.(ya?ml)$/i.test(f));
  const manifestFiles = yamlFiles.filter((f) => looksLikeK8sManifest(fs.readFileSync(f, "utf8")));
  if (manifestFiles.length === 0) return { findings, passed: [] };

  let anyWorkloadWithContainers = false;
  let anyPrivileged = false;
  let anyHostAccess = false;
  let anyDangerousCaps = false;
  let anyRbac = false;
  let anyWildcardRbac = false;
  let anyMissingLimits = false;
  let anySecretLiteral = false;

  for (const file of manifestFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);
    const docs = text.split(/^---\s*$/m).filter((d) => d.trim());

    for (const doc of docs) {
      const kind = getKind(doc);
      if (!kind) continue;

      if (HAS_CONTAINERS.test(doc)) {
        anyWorkloadWithContainers = true;

        if (PRIVILEGED_CONTAINER.test(doc)) {
          anyPrivileged = true;
          findings.push({
            severity: "critical",
            category: "Infrastructure",
            title: `${kind} runs a container with privileged: true`,
            detail: "A privileged container has essentially full access to the host — this removes most of the isolation a container is supposed to provide.",
            file: rel,
            line: null,
            remediation: "Remove privileged: true. If specific capabilities are needed, grant only those via securityContext.capabilities.add instead.",
          });
        }
        if (RUN_AS_NON_ROOT_FALSE.test(doc)) {
          findings.push({
            severity: "medium",
            category: "Infrastructure",
            title: `${kind} explicitly allows running as root (runAsNonRoot: false)`,
            detail: "runAsNonRoot is explicitly set to false, permitting the container to run as UID 0.",
            file: rel,
            line: null,
            remediation: "Set runAsNonRoot: true and runAsUser to a non-zero UID in the pod or container securityContext.",
          });
        }
        if (HOST_NETWORK.test(doc)) {
          anyHostAccess = true;
          findings.push({
            severity: "high",
            category: "Infrastructure",
            title: `${kind} uses hostNetwork: true`,
            detail: "The pod shares the host's network namespace, giving it access to the host's network interfaces and any service bound to localhost on the node.",
            file: rel,
            line: null,
            remediation: "Remove hostNetwork: true unless the workload specifically needs host networking (e.g. a CNI plugin or node-level monitoring agent).",
          });
        }
        if (HOST_PATH_VOLUME.test(doc)) {
          anyHostAccess = true;
          findings.push({
            severity: "high",
            category: "Infrastructure",
            title: `${kind} mounts a hostPath volume`,
            detail: "hostPath volumes give the container direct access to a path on the node's filesystem, which can be used to escape the container or affect other workloads on the same node.",
            file: rel,
            line: null,
            remediation: "Use a PersistentVolumeClaim, ConfigMap, or Secret volume instead of hostPath where possible.",
          });
        }
        if (DANGEROUS_CAPS.test(doc) || DANGEROUS_CAPS_LIST_ITEM.test(doc)) {
          anyDangerousCaps = true;
          findings.push({
            severity: "high",
            category: "Infrastructure",
            title: `${kind} adds a dangerous Linux capability`,
            detail: "One or more capabilities that grant broad host or kernel access (e.g. SYS_ADMIN, NET_ADMIN, ALL) are added to a container.",
            file: rel,
            line: null,
            remediation: "Drop ALL capabilities by default (capabilities: drop: [ALL]) and add back only the specific capability the workload actually needs.",
          });
        }
        if (NODEPORT_OR_LB.test(doc)) {
          findings.push({
            severity: "low",
            category: "Infrastructure",
            title: `${kind} is exposed via NodePort or LoadBalancer`,
            detail: "This service type exposes the workload outside the cluster. This is often intentional — confirm it's meant to be publicly reachable.",
            file: rel,
            line: null,
            remediation: "Use ClusterIP with an Ingress if the service should go through a controlled entry point rather than being directly exposed.",
          });
        }
        if (SECRET_ENV_LITERAL.test(doc)) {
          anySecretLiteral = true;
          findings.push({
            severity: "high",
            category: "Infrastructure",
            title: `${kind} sets a secret-like environment variable to a literal value`,
            detail: "An environment variable named like a credential (PASSWORD/SECRET/TOKEN/KEY) is set with a literal `value:` instead of `valueFrom.secretKeyRef`. Plain env vars are visible via the pod spec and process environment.",
            file: rel,
            line: null,
            remediation: "Store the value in a Kubernetes Secret and reference it with valueFrom.secretKeyRef instead of a literal value.",
          });
        }
        if (!RESOURCE_LIMITS.test(doc)) {
          anyMissingLimits = true;
          findings.push({
            severity: "medium",
            category: "Infrastructure",
            title: `${kind} has no resource limits set`,
            detail: "No resources.limits block was found for this workload's containers. Without limits, a runaway or compromised container can consume unbounded CPU/memory on the node.",
            file: rel,
            line: null,
            remediation: "Set resources.limits.cpu and resources.limits.memory for every container.",
          });
        }
      }

      if (kind === "Role" || kind === "ClusterRole") {
        anyRbac = true;
        if (WILDCARD_RBAC.test(doc)) {
          anyWildcardRbac = true;
          findings.push({
            severity: "critical",
            category: "Infrastructure",
            title: `${kind} grants wildcard access (apiGroups/resources/verbs all "*")`,
            detail: "This role grants every verb on every resource in every API group — equivalent to cluster-admin for anything bound to it.",
            file: rel,
            line: null,
            remediation: "Scope apiGroups, resources, and verbs to exactly what the role's bound identity needs.",
          });
        }
      }
    }
  }

  const passed: Pass[] = [];
  if (anyWorkloadWithContainers && !anyPrivileged) passed.push({ category: "Infrastructure", title: "No privileged containers detected in scanned manifests" });
  if (anyWorkloadWithContainers && !anyHostAccess) passed.push({ category: "Infrastructure", title: "No hostNetwork or hostPath usage detected" });
  if (anyWorkloadWithContainers && !anyDangerousCaps) passed.push({ category: "Infrastructure", title: "No dangerous Linux capabilities added" });
  if (anyRbac && !anyWildcardRbac) passed.push({ category: "Infrastructure", title: "No wildcard RBAC roles detected" });
  if (anyWorkloadWithContainers && !anyMissingLimits) passed.push({ category: "Infrastructure", title: "Resource limits set on scanned workloads" });
  if (anyWorkloadWithContainers && !anySecretLiteral) passed.push({ category: "Infrastructure", title: "No secret-like environment variables set as literal values" });

  return { findings, passed };
}
