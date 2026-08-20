import { test } from "node:test";
import assert from "node:assert/strict";
import { readTaskEnv, MissingTaskEnvError } from "../src/scanner/taskEntrypoint";

const UPLOAD_ENV = {
  NETTLE_SCAN_MODE: "upload",
  NETTLE_SCAN_JOB_ID: "job-1",
  NETTLE_SCAN_CALLBACK_URL: "https://example.awsapprunner.com",
  NETTLE_SCAN_CALLBACK_TOKEN: "sometoken",
  NETTLE_SCAN_S3_BUCKET: "bucket",
  NETTLE_SCAN_S3_KEY: "uploads/job-1.zip",
};

const REPO_ENV = {
  NETTLE_SCAN_MODE: "repo",
  NETTLE_SCAN_JOB_ID: "job-2",
  NETTLE_SCAN_CALLBACK_URL: "https://example.awsapprunner.com",
  NETTLE_SCAN_CALLBACK_TOKEN: "sometoken",
  NETTLE_SCAN_REPO_URL: "https://github.com/octocat/Hello-World",
  NETTLE_SCAN_REPO_BRANCH: "main",
};

test("readTaskEnv parses a well-formed upload-mode environment", () => {
  const env = readTaskEnv(UPLOAD_ENV as unknown as NodeJS.ProcessEnv);
  assert.equal(env.mode, "upload");
  assert.equal(env.jobId, "job-1");
  assert.equal(env.s3Bucket, "bucket");
  assert.equal(env.s3Key, "uploads/job-1.zip");
});

test("readTaskEnv parses a well-formed repo-mode environment, defaulting repoToken to null", () => {
  const env = readTaskEnv(REPO_ENV as unknown as NodeJS.ProcessEnv);
  assert.equal(env.mode, "repo");
  assert.equal(env.repoUrl, "https://github.com/octocat/Hello-World");
  assert.equal(env.repoBranch, "main");
  assert.equal(env.repoToken, null);
});

test("readTaskEnv rejects a missing or invalid NETTLE_SCAN_MODE", () => {
  assert.throws(() => readTaskEnv({} as unknown as NodeJS.ProcessEnv), MissingTaskEnvError);
  assert.throws(
    () => readTaskEnv({ NETTLE_SCAN_MODE: "delete-everything" } as unknown as NodeJS.ProcessEnv),
    MissingTaskEnvError
  );
});

test("readTaskEnv rejects an upload-mode environment missing a required field", () => {
  for (const missing of ["NETTLE_SCAN_JOB_ID", "NETTLE_SCAN_CALLBACK_URL", "NETTLE_SCAN_CALLBACK_TOKEN", "NETTLE_SCAN_S3_BUCKET", "NETTLE_SCAN_S3_KEY"]) {
    const partial = { ...UPLOAD_ENV, [missing]: undefined };
    assert.throws(() => readTaskEnv(partial as unknown as NodeJS.ProcessEnv), MissingTaskEnvError, `expected ${missing} to be required`);
  }
});

test("readTaskEnv rejects a repo-mode environment missing NETTLE_SCAN_REPO_URL", () => {
  const partial = { ...REPO_ENV, NETTLE_SCAN_REPO_URL: undefined };
  assert.throws(() => readTaskEnv(partial as unknown as NodeJS.ProcessEnv), MissingTaskEnvError);
});

test("readTaskEnv treats an unset NETTLE_SCAN_REPO_TOKEN as null, not a required field", () => {
  const env = readTaskEnv(REPO_ENV as unknown as NodeJS.ProcessEnv);
  assert.equal(env.repoToken, null);
});
