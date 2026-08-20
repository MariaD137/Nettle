import { test } from "node:test";
import assert from "node:assert/strict";
import { App } from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { NettleNetworkStack } from "../lib/network-stack";
import { NettleScannerStack } from "../lib/scanner-stack";

/**
 * Regression coverage for the read-only-root-filesystem + writable-/tmp
 * fix: the scanner task's root filesystem is read-only
 * (readonlyRootFilesystem: true), but taskEntrypoint.ts still needs
 * somewhere to write the downloaded zip, its extraction directory, and the
 * git clone directory (all under os.tmpdir(), i.e. /tmp). Without a tmpfs
 * mounted there, every real scan fails immediately with
 * "EROFS: read-only file system" the moment it tries to write a file —
 * this test fails loudly if that tmpfs mount is ever removed or
 * repointed, and would have caught the original bug before it reached a
 * synthesized template.
 */
function synthScannerTemplate(): Template {
  const app = new App();
  const env = { account: "123456789012", region: "us-east-1" };
  const network = new NettleNetworkStack(app, "TestScannerNetwork", { env });
  const scanner = new NettleScannerStack(app, "TestScannerStack", { env, vpc: network.vpc });
  return Template.fromStack(scanner);
}

test("scanner task definition mounts a writable tmpfs at /tmp", () => {
  const template = synthScannerTemplate();

  template.hasResourceProperties("AWS::ECS::TaskDefinition", {
    ContainerDefinitions: Match.arrayWith([
      Match.objectLike({
        Name: "scanner",
        LinuxParameters: Match.objectLike({
          Tmpfs: Match.arrayWith([
            Match.objectLike({
              ContainerPath: "/tmp",
            }),
          ]),
        }),
      }),
    ]),
  });
});

test("the /tmp tmpfs is sized to comfortably cover the scanner's existing archive limits (>= 500MB aggregate cap)", () => {
  const template = synthScannerTemplate();
  const taskDefs = template.findResources("AWS::ECS::TaskDefinition");
  const [taskDef] = Object.values(taskDefs) as any[];
  const container = taskDef.Properties.ContainerDefinitions.find((c: any) => c.Name === "scanner");
  const tmpfs = container.LinuxParameters.Tmpfs.find((t: any) => t.ContainerPath === "/tmp");

  assert.ok(tmpfs, "expected a tmpfs entry mounted at /tmp");
  // safeExtraction.ts's own aggregate archive cap is 500MB — the tmpfs
  // has to hold at least that, plus the original compressed zip and any
  // git-clone/Semgrep scratch space, so this asserts real headroom above
  // that floor rather than just "greater than zero".
  assert.ok(tmpfs.Size >= 500, `expected /tmp tmpfs size (${tmpfs.Size} MiB) to be at least 500 MiB`);
});

test("the scanner container's root filesystem stays read-only even with the /tmp tmpfs present", () => {
  const template = synthScannerTemplate();

  template.hasResourceProperties("AWS::ECS::TaskDefinition", {
    ContainerDefinitions: Match.arrayWith([
      Match.objectLike({
        Name: "scanner",
        ReadonlyRootFilesystem: true,
      }),
    ]),
  });
});

test("no persistent volume (S3, EFS, host bind mount) is attached to the scanner task — the tmpfs is the only writable area", () => {
  const template = synthScannerTemplate();
  const taskDefs = template.findResources("AWS::ECS::TaskDefinition");
  const [taskDef] = Object.values(taskDefs) as any[];

  // Volumes/MountPoints would appear here for an EFS/host/bind mount; a
  // pure in-memory tmpfs (set via LinuxParameters, asserted above) needs
  // neither, so both should stay absent.
  assert.equal(taskDef.Properties.Volumes, undefined, "expected no ECS Volumes (S3/EFS/host mounts) on the scanner task");
  const container = taskDef.Properties.ContainerDefinitions.find((c: any) => c.Name === "scanner");
  assert.equal(container.MountPoints, undefined, "expected no container MountPoints on the scanner task");
});
