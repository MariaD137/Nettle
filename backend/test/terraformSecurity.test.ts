import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { scanTerraformSecurity } from "../src/scanner/terraformSecurity";

function withFixture(name: string, content: string, fn: (files: string[], root: string) => void) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-"));
  const file = path.join(root, name);
  fs.writeFileSync(file, content);
  try {
    fn([file], root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test("returns no findings when there are no .tf files", () => {
  const { findings, passed } = scanTerraformSecurity([], "/nonexistent");
  assert.deepEqual(findings, []);
  assert.deepEqual(passed, []);
});

test("flags a publicly-readable S3 bucket ACL", () => {
  withFixture(
    "s3.tf",
    `resource "aws_s3_bucket" "logs" {\n  bucket = "my-logs"\n  acl    = "public-read"\n  server_side_encryption_configuration {}\n}\n`,
    (files, root) => {
      const { findings } = scanTerraformSecurity(files, root);
      assert.ok(findings.some((f) => f.title === "S3 bucket may be publicly accessible" && f.severity === "critical"));
    }
  );
});

test("flags an S3 bucket with no server-side encryption configuration", () => {
  withFixture(
    "s3.tf",
    `resource "aws_s3_bucket" "logs" {\n  bucket = "my-logs"\n  acl    = "private"\n}\n`,
    (files, root) => {
      const { findings } = scanTerraformSecurity(files, root);
      assert.ok(findings.some((f) => f.title === "S3 bucket has no server-side encryption configuration"));
    }
  );
});

test("does not flag a private, encrypted S3 bucket", () => {
  withFixture(
    "s3.tf",
    `resource "aws_s3_bucket" "logs" {\n  bucket = "my-logs"\n  acl    = "private"\n  server_side_encryption_configuration {\n    rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }\n  }\n}\n`,
    (files, root) => {
      const { findings, passed } = scanTerraformSecurity(files, root);
      assert.deepEqual(findings, []);
      assert.ok(passed.some((p) => p.title === "No publicly-writable S3 bucket ACLs detected"));
    }
  );
});

test("flags a wildcard IAM policy statement (Action=* and Resource=*)", () => {
  withFixture(
    "iam.tf",
    `resource "aws_iam_policy" "admin" {\n  policy = jsonencode({\n    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]\n  })\n}\n`,
    (files, root) => {
      const { findings } = scanTerraformSecurity(files, root);
      assert.ok(findings.some((f) => f.title.includes("wildcard action on wildcard resource")));
    }
  );
});

test("does not flag a scoped IAM policy", () => {
  withFixture(
    "iam.tf",
    `resource "aws_iam_policy" "readonly" {\n  policy = jsonencode({\n    Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::my-bucket/*" }]\n  })\n}\n`,
    (files, root) => {
      const { findings, passed } = scanTerraformSecurity(files, root);
      assert.deepEqual(findings, []);
      assert.ok(passed.some((p) => p.title === "No wildcard (*:*) IAM policy statements detected"));
    }
  );
});

test("flags a publicly-accessible RDS instance and missing storage encryption", () => {
  withFixture(
    "rds.tf",
    `resource "aws_db_instance" "main" {\n  identifier          = "prod-db"\n  publicly_accessible = true\n}\n`,
    (files, root) => {
      const { findings } = scanTerraformSecurity(files, root);
      assert.ok(findings.some((f) => f.title === "RDS instance is configured as publicly accessible"));
      assert.ok(findings.some((f) => f.title === "RDS instance does not set storage_encrypted = true"));
    }
  );
});

test("does not flag a private, encrypted RDS instance", () => {
  withFixture(
    "rds.tf",
    `resource "aws_db_instance" "main" {\n  identifier          = "prod-db"\n  publicly_accessible = false\n  storage_encrypted   = true\n}\n`,
    (files, root) => {
      const { findings } = scanTerraformSecurity(files, root);
      assert.deepEqual(findings, []);
    }
  );
});

test("flags a security group with unrestricted ingress on a sensitive port as critical", () => {
  withFixture(
    "sg.tf",
    `resource "aws_security_group" "db" {\n  ingress {\n    from_port   = 5432\n    to_port     = 5432\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n`,
    (files, root) => {
      const { findings } = scanTerraformSecurity(files, root);
      const f = findings.find((f) => f.title.includes("sensitive port"));
      assert.ok(f);
      assert.equal(f!.severity, "critical");
    }
  );
});

test("flags unrestricted ingress on a non-sensitive port as high, not critical", () => {
  withFixture(
    "sg.tf",
    `resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 8080\n    to_port     = 8080\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n`,
    (files, root) => {
      const { findings } = scanTerraformSecurity(files, root);
      const f = findings.find((f) => f.title === "Security group allows unrestricted ingress (0.0.0.0/0)");
      assert.ok(f);
      assert.equal(f!.severity, "high");
    }
  );
});

test("does not flag a security group restricted to a known CIDR", () => {
  withFixture(
    "sg.tf",
    `resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    protocol    = "tcp"\n    cidr_blocks = ["10.0.0.0/16"]\n  }\n}\n`,
    (files, root) => {
      const { findings, passed } = scanTerraformSecurity(files, root);
      assert.deepEqual(findings, []);
      assert.ok(passed.some((p) => p.title === "No unrestricted (0.0.0.0/0) security group ingress detected"));
    }
  );
});
