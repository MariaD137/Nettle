import { S3Client, GetObjectCommand, PutObjectCommand } from "@aws-sdk/client-s3";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { runScan } from "./scanner";

/**
 * The isolated scan worker's entrypoint — what actually runs inside the
 * Fargate task scan-worker-stack.ts provisions, invoked via that task
 * definition's `command: ["node", "dist/scanWorker.js"]` override instead
 * of the API's own `dist/index.js`. Same image, same compiled scanner code
 * (runScan() below is the exact function scanner/index.ts's own callers
 * use — no second scan engine), different entrypoint.
 *
 * This process has none of the API's own capabilities: no DATABASE_URL, no
 * Stripe/SES secrets (scan-worker-stack.ts's task role grants exactly two
 * scoped S3 actions and nothing else — see that file), and no network path
 * to anything but S3 (network-stack.ts's isolated subnets). It reads its
 * job from environment variables set at RunTask time
 * (backend/src/scanner/isolatedExecution.ts), not from any request it
 * receives — this process serves no HTTP, accepts no inbound connection at
 * all.
 *
 * On any failure, this deliberately does NOT write anything to the results
 * key — only exits non-zero. isolatedExecution.ts's orchestration checks
 * the task's real exit code and the presence of a results object before
 * ever treating a scan as complete; writing a "failed" placeholder here
 * would risk being misread as a real report by anything that doesn't check
 * the exit code first.
 */
async function main(): Promise<void> {
  const scanId = process.env.SCAN_ID;
  const bucket = process.env.SCAN_WORKSPACE_BUCKET;
  const workspaceKey = process.env.SCAN_WORKSPACE_KEY;
  const resultsKey = process.env.SCAN_RESULTS_KEY;

  if (!scanId || !bucket || !workspaceKey || !resultsKey) {
    console.error("[scan-worker] missing one or more required environment variables (SCAN_ID, SCAN_WORKSPACE_BUCKET, SCAN_WORKSPACE_KEY, SCAN_RESULTS_KEY)");
    process.exit(1);
  }

  const s3 = new S3Client({});
  const workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "scan-worker-workspace-"));
  const archivePath = path.join(os.tmpdir(), `${scanId}-workspace.tar.gz`);

  try {
    const object = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: workspaceKey }));
    if (!object.Body) throw new Error("Workspace object had no body");
    const bytes = await object.Body.transformToByteArray();
    fs.writeFileSync(archivePath, bytes);
    execFileSync("tar", ["-xzf", archivePath, "-C", workspaceDir], { timeout: 60_000 });

    const report = runScan(workspaceDir);

    await s3.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: resultsKey,
        Body: JSON.stringify(report),
        ContentType: "application/json",
      })
    );

    console.log(`[scan-worker] scan ${scanId} completed`);
    process.exit(0);
  } catch (err) {
    console.error(`[scan-worker] scan ${scanId} failed: ${(err as Error).message}`);
    process.exit(1);
  } finally {
    fs.rmSync(workspaceDir, { recursive: true, force: true });
    fs.rmSync(archivePath, { force: true });
  }
}

main();
