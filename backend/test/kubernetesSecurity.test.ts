import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { scanKubernetesSecurity } from "../src/scanner/kubernetesSecurity";

function withFixture(name: string, content: string, fn: (files: string[], root: string) => void) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "k8s-test-"));
  const file = path.join(root, name);
  fs.writeFileSync(file, content);
  try {
    fn([file], root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test("returns no findings when there are no k8s manifests", () => {
  const { findings, passed } = scanKubernetesSecurity([], "/nonexistent");
  assert.deepEqual(findings, []);
  assert.deepEqual(passed, []);
});

test("ignores a .yaml file that lacks apiVersion/kind (e.g. a CI config)", () => {
  withFixture(
    "config.yaml",
    `steps:\n  - run: npm test\n`,
    (files, root) => {
      const { findings, passed } = scanKubernetesSecurity(files, root);
      assert.deepEqual(findings, []);
      assert.deepEqual(passed, []);
    }
  );
});

test("flags a privileged container", () => {
  withFixture(
    "deploy.yaml",
    `apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          securityContext:\n            privileged: true\n`,
    (files, root) => {
      const { findings } = scanKubernetesSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes("privileged: true") && f.severity === "critical"));
    }
  );
});

test("flags hostNetwork and hostPath usage", () => {
  withFixture(
    "deploy.yaml",
    `apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n        - name: app\n          volumeMounts:\n            - mountPath: /host\n      volumes:\n        - name: hostvol\n          hostPath:\n            path: /etc\n`,
    (files, root) => {
      const { findings } = scanKubernetesSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes("hostNetwork: true")));
      assert.ok(findings.some((f) => f.title.includes("hostPath volume")));
    }
  );
});

test("flags a dangerous added Linux capability", () => {
  withFixture(
    "deploy.yaml",
    `apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          securityContext:\n            capabilities:\n              add: ["SYS_ADMIN"]\n`,
    (files, root) => {
      const { findings } = scanKubernetesSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes("dangerous Linux capability")));
    }
  );
});

test("flags a secret-like env var set as a literal value instead of secretKeyRef", () => {
  withFixture(
    "deploy.yaml",
    `apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          env:\n            - name: DB_PASSWORD\n              value: "hunter2"\n          resources:\n            limits:\n              cpu: "500m"\n              memory: "256Mi"\n`,
    (files, root) => {
      const { findings } = scanKubernetesSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes("literal value")));
    }
  );
});

test("does not flag a secret sourced from secretKeyRef", () => {
  withFixture(
    "deploy.yaml",
    `apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          env:\n            - name: DB_PASSWORD\n              valueFrom:\n                secretKeyRef:\n                  name: db-secret\n                  key: password\n          resources:\n            limits:\n              cpu: "500m"\n              memory: "256Mi"\n`,
    (files, root) => {
      const { findings, passed } = scanKubernetesSecurity(files, root);
      assert.equal(findings.some((f) => f.title.includes("literal value")), false);
      assert.ok(passed.some((p) => p.title.includes("secret-like environment variables")));
    }
  );
});

test("flags a workload with no resource limits", () => {
  withFixture(
    "deploy.yaml",
    `apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: myapp:1.0\n`,
    (files, root) => {
      const { findings } = scanKubernetesSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes("no resource limits")));
    }
  );
});

test("flags a wildcard ClusterRole", () => {
  withFixture(
    "rbac.yaml",
    `apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: super-admin\nrules:\n  - apiGroups: ["*"]\n    resources: ["*"]\n    verbs: ["*"]\n`,
    (files, root) => {
      const { findings } = scanKubernetesSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes("wildcard access") && f.severity === "critical"));
    }
  );
});

test("does not flag a scoped Role", () => {
  withFixture(
    "rbac.yaml",
    `apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: pod-reader\nrules:\n  - apiGroups: [""]\n    resources: ["pods"]\n    verbs: ["get", "list"]\n`,
    (files, root) => {
      const { findings, passed } = scanKubernetesSecurity(files, root);
      assert.deepEqual(findings, []);
      assert.ok(passed.some((p) => p.title === "No wildcard RBAC roles detected"));
    }
  );
});

test("produces zero findings for a fully hardened multi-document manifest", () => {
  withFixture(
    "deploy.yaml",
    [
      "apiVersion: apps/v1",
      "kind: Deployment",
      "spec:",
      "  template:",
      "    spec:",
      "      containers:",
      "        - name: app",
      "          image: myapp:1.0",
      "          securityContext:",
      "            runAsNonRoot: true",
      "          resources:",
      "            limits:",
      '              cpu: "500m"',
      '              memory: "256Mi"',
      "---",
      "apiVersion: v1",
      "kind: Service",
      "spec:",
      "  type: ClusterIP",
      "",
    ].join("\n"),
    (files, root) => {
      const { findings } = scanKubernetesSecurity(files, root);
      assert.deepEqual(findings, []);
    }
  );
});
