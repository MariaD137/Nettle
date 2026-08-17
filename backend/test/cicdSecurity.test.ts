import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { scanCicdSecurity } from "../src/scanner/cicdSecurity";

function withFixture(content: string, fn: (files: string[], root: string) => void, filename = "ci.yml") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-test-"));
  const workflowsDir = path.join(root, ".github", "workflows");
  fs.mkdirSync(workflowsDir, { recursive: true });
  const file = path.join(workflowsDir, filename);
  fs.writeFileSync(file, content);
  try {
    fn([file], root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test("returns no findings when there are no workflow files", () => {
  const { findings, passed } = scanCicdSecurity([], "/nonexistent");
  assert.deepEqual(findings, []);
  assert.deepEqual(passed, []);
});

test("ignores yaml files outside .github/workflows", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cicd-test-"));
  const file = path.join(root, "docker-compose.yml");
  fs.writeFileSync(file, "pull_request_target:\npermissions: write-all\n");
  try {
    const { findings } = scanCicdSecurity([file], root);
    assert.deepEqual(findings, []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("flags pull_request_target combined with checking out the PR's own head", () => {
  withFixture(
    `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v3\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n`,
    (files, root) => {
      const { findings } = scanCicdSecurity(files, root);
      const f = findings.find((f) => f.title.includes("checks out the PR's own head ref"));
      assert.ok(f);
      assert.equal(f!.severity, "critical");
    }
  );
});

test("does not flag pull_request_target that checks out the default ref", () => {
  withFixture(
    `on:\n  pull_request_target:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bde6f26a44ffff9c5b813e91\n`,
    (files, root) => {
      const { findings, passed } = scanCicdSecurity(files, root);
      assert.equal(findings.some((f) => f.title.includes("checks out the PR's own head ref")), false);
      assert.ok(passed.some((p) => p.title.includes("No pull_request_target")));
    }
  );
});

test("flags permissions: write-all", () => {
  withFixture(
    `on:\n  push:\npermissions: write-all\njobs:\n  build:\n    steps:\n      - run: echo hi\n`,
    (files, root) => {
      const { findings } = scanCicdSecurity(files, root);
      const f = findings.find((f) => f.title.includes("broad GITHUB_TOKEN permissions"));
      assert.ok(f);
      assert.equal(f!.severity, "medium");
    }
  );
});

test("flags contents: write as high severity when combined with pull_request_target", () => {
  withFixture(
    `on:\n  pull_request_target:\npermissions:\n  contents: write\njobs:\n  build:\n    steps:\n      - run: echo hi\n`,
    (files, root) => {
      const { findings } = scanCicdSecurity(files, root);
      const f = findings.find((f) => f.title.includes("broad GITHUB_TOKEN permissions"));
      assert.ok(f);
      assert.equal(f!.severity, "high");
    }
  );
});

test("flags a workflow with no permissions block at all", () => {
  withFixture(
    `on:\n  push:\njobs:\n  build:\n    steps:\n      - run: echo hi\n`,
    (files, root) => {
      const { findings } = scanCicdSecurity(files, root);
      assert.ok(findings.some((f) => f.title === "Workflow has no explicit permissions block"));
    }
  );
});

test("does not flag a missing-permissions finding when permissions are scoped to read", () => {
  withFixture(
    `on:\n  push:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - run: echo hi\n`,
    (files, root) => {
      const { findings, passed } = scanCicdSecurity(files, root);
      assert.equal(findings.some((f) => f.title === "Workflow has no explicit permissions block"), false);
      assert.equal(findings.some((f) => f.title.includes("broad GITHUB_TOKEN")), false);
      assert.ok(passed.some((p) => p.title.includes("declare an explicit permissions block")));
    }
  );
});

test("flags curl piped into bash", () => {
  withFixture(
    `on:\n  push:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - run: curl -sSL https://get.example.com/install.sh | bash\n`,
    (files, root) => {
      const { findings } = scanCicdSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes("pipes a downloaded script")));
    }
  );
});

test("flags a third-party action pinned to a mutable branch ref", () => {
  withFixture(
    `on:\n  push:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: some-org/some-action@main\n`,
    (files, root) => {
      const { findings } = scanCicdSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes('some-org/some-action') && f.title.includes("not pinned")));
    }
  );
});

test("flags a third-party action pinned to a short version tag", () => {
  withFixture(
    `on:\n  push:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: some-org/some-action@v3\n`,
    (files, root) => {
      const { findings } = scanCicdSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes("not pinned")));
    }
  );
});

test("does not flag an action pinned to a full commit SHA", () => {
  withFixture(
    `on:\n  push:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bde6f26a44ffff9c5b813e91\n`,
    (files, root) => {
      const { findings, passed } = scanCicdSecurity(files, root);
      assert.equal(findings.some((f) => f.title.includes("not pinned")), false);
      assert.ok(passed.some((p) => p.title.includes("pinned to a commit SHA")));
    }
  );
});

test("produces zero findings for a fully hardened workflow", () => {
  withFixture(
    `on:\n  push:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bde6f26a44ffff9c5b813e91\n      - run: npm test\n`,
    (files, root) => {
      const { findings } = scanCicdSecurity(files, root);
      assert.deepEqual(findings, []);
    }
  );
});
