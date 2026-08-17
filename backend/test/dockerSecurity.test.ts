import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { scanDockerSecurity } from "../src/scanner/dockerSecurity";

function withFixture(name: string, content: string, fn: (files: string[], root: string) => void) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "docker-test-"));
  const file = path.join(root, name);
  fs.writeFileSync(file, content);
  try {
    fn([file], root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test("returns no findings when there are no Dockerfiles", () => {
  const { findings, passed } = scanDockerSecurity([], "/nonexistent");
  assert.deepEqual(findings, []);
  assert.deepEqual(passed, []);
});

test("flags a Dockerfile with no USER instruction", () => {
  withFixture(
    "Dockerfile",
    `FROM node:20.11.1@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678\nCOPY . .\nCMD ["node", "index.js"]\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n`,
    (files, root) => {
      const { findings } = scanDockerSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes("no USER instruction")));
    }
  );
});

test("does not flag a Dockerfile that sets USER", () => {
  withFixture(
    "Dockerfile",
    `FROM node:20.11.1@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678\nRUN useradd -m appuser\nUSER appuser\nCMD ["node", "index.js"]\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n`,
    (files, root) => {
      const { findings, passed } = scanDockerSecurity(files, root);
      assert.equal(findings.some((f) => f.title.includes("no USER instruction")), false);
      assert.ok(passed.some((p) => p.title === "Dockerfile(s) specify a non-root USER"));
    }
  );
});

test("flags a hardcoded secret-like literal in an ENV instruction", () => {
  withFixture(
    "Dockerfile",
    `FROM node:20.11.1@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678\nUSER appuser\nENV STRIPE_SECRET_KEY=sk_live_abcdefghijklmnop1234\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n`,
    (files, root) => {
      const { findings } = scanDockerSecurity(files, root);
      const f = findings.find((f) => f.title.includes("Hardcoded credential"));
      assert.ok(f);
      assert.equal(f!.severity, "critical");
      assert.equal(f!.line, 3);
    }
  );
});

test("does not flag an ENV var referencing a build ARG rather than a literal", () => {
  withFixture(
    "Dockerfile",
    `FROM node:20.11.1@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678\nARG API_KEY\nUSER appuser\nENV API_KEY=$API_KEY\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n`,
    (files, root) => {
      const { findings } = scanDockerSecurity(files, root);
      assert.equal(findings.some((f) => f.title.includes("Hardcoded credential")), false);
    }
  );
});

test("flags an unpinned :latest base image", () => {
  withFixture(
    "Dockerfile",
    `FROM node:latest\nUSER appuser\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n`,
    (files, root) => {
      const { findings } = scanDockerSecurity(files, root);
      assert.ok(findings.some((f) => f.title === "Base image is not pinned to a specific version"));
    }
  );
});

test("does not flag a multi-stage build's reference to an earlier named stage", () => {
  withFixture(
    "Dockerfile",
    `FROM node:20.11.1@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678 AS builder\nRUN npm run build\n\nFROM builder AS runtime\nUSER appuser\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n`,
    (files, root) => {
      const { findings } = scanDockerSecurity(files, root);
      assert.equal(findings.some((f) => f.title === "Base image is not pinned to a specific version"), false);
    }
  );
});

test("flags a missing HEALTHCHECK instruction", () => {
  withFixture(
    "Dockerfile",
    `FROM node:20.11.1@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678\nUSER appuser\nCMD ["node", "index.js"]\n`,
    (files, root) => {
      const { findings } = scanDockerSecurity(files, root);
      assert.ok(findings.some((f) => f.title === "Dockerfile has no HEALTHCHECK instruction"));
    }
  );
});

test("matches Dockerfile variants like web.Dockerfile", () => {
  withFixture(
    "web.Dockerfile",
    `FROM node:latest\n`,
    (files, root) => {
      const { findings } = scanDockerSecurity(files, root);
      assert.ok(findings.length > 0);
    }
  );
});

test("produces zero findings for a fully hardened Dockerfile", () => {
  withFixture(
    "Dockerfile",
    `FROM node:20.11.1@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678 AS builder\nRUN npm run build\n\nFROM builder AS runtime\nRUN useradd -m appuser\nUSER appuser\nCMD ["node", "index.js"]\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n`,
    (files, root) => {
      const { findings } = scanDockerSecurity(files, root);
      assert.deepEqual(findings, []);
    }
  );
});
