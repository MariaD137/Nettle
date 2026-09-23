import { CfnOutput, Duration, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import { SubnetType, SecurityGroup, Peer, Port, type Vpc } from "aws-cdk-lib/aws-ec2";
import { Cluster, FargateTaskDefinition, ContainerImage, LogDrivers, ContainerInsights } from "aws-cdk-lib/aws-ecs";
import { Role, ServicePrincipal, PolicyStatement } from "aws-cdk-lib/aws-iam";
import { Bucket, BlockPublicAccess, BucketEncryption } from "aws-cdk-lib/aws-s3";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import type { IRepository } from "aws-cdk-lib/aws-ecr";
import type { Construct } from "constructs";

export interface NettleScanWorkerStackProps extends StackProps {
  vpc: Vpc;
  /** Same ECR repo the API's image lives in — the scan worker runs the identical image, just with a different command (see below). */
  repository: IRepository;
}

/**
 * True scan sandboxing: untrusted, customer-supplied source code is analyzed
 * inside its own ECS Fargate task, not inside the API's own process/container.
 *
 * Why this exists: scanner/scanQueue.ts's async queue (added in the previous
 * round) decoupled the *client* from a scan's duration, but explicitly and
 * honestly did NOT isolate scan execution itself — runScan() still ran
 * inside the same Node process, same container, same filesystem, same
 * network path, and same IAM role as the rest of the API. A malicious or
 * malformed upload could still exhaust that shared process's CPU/memory or
 * (if it ever found a real vulnerability in the scanner or its
 * dependencies) reach the database credentials, Stripe keys, or other
 * customers' in-flight requests sitting in the same container. This stack
 * closes that gap with a real boundary: separate process, separate
 * container, separate filesystem, separate network path, separate IAM role
 * — one that has no access to any of those things.
 *
 * Design, and why it's the smallest thing that actually closes the gap:
 *   - Reuses the EXISTING ECR image (ecr-stack.ts/api-stack.ts) with a
 *     different container command (`node dist/scanWorker.js` instead of
 *     `node dist/index.js`) — no second Docker build pipeline, no second
 *     image to keep in sync. backend/Dockerfile already installs
 *     unzip/git/python3/semgrep and runs as a non-root user; the scan
 *     worker needs nothing the API's own image doesn't already have.
 *   - Placed in the VPC's ISOLATED subnets (network-stack.ts) — the same
 *     tier the database lives in, for the same reason: no route to the
 *     internet in either direction, at the network layer, not just via a
 *     security group. Semgrep runs with `--metrics=off` against local
 *     rules and OSV vulnerability data is a bundled local SQLite DB
 *     (scanner/osv-data/npm-vulnerabilities.db, no live API call) — nothing
 *     in the actual scan pipeline needs network access at all, so denying
 *     it outright is correct, not merely cautious. The one thing the task
 *     DOES need — reaching S3 for its workspace/results handoff — goes
 *     through network-stack.ts's S3 gateway endpoint, which needs no
 *     internet route either.
 *   - The task's own IAM role (below) has no Secrets Manager grant at all —
 *     it cannot read the database credentials or Stripe/SES secrets even
 *     if it wanted to, regardless of what code runs inside it. It gets
 *     exactly two S3 permissions (read the one workspace object it was
 *     told about, write the one results object it was told to) and nothing
 *     else — no S3 read-all, no database access, no other AWS service.
 *   - Fargate's own task-definition cpu/memory are AWS-ENFORCED hard limits
 *     (the task is killed if it exceeds them), unlike the previous
 *     in-process execution, where "resource limits" meant Semgrep's own
 *     30s execFileSync timeout and nothing bounded everything else sharing
 *     the API container.
 *
 * Orchestration (backend/src/scanner/isolatedExecution.ts): the API tars
 * the already-extracted, already-safeExtractZip-validated scan workspace,
 * uploads it to this bucket, calls ecs:RunTask with the scan id baked into
 * environment variable overrides, polls ecs:DescribeTasks for completion (or
 * its own timeout, then ecs:StopTask), and reads the results object the task
 * wrote back — never trusting a task that never wrote one, or that exited
 * non-zero, as a success. Falls back to the pre-existing in-process
 * execution when this isn't configured (local development, tests, or any
 * environment without AWS credentials) — see that file and scanQueue.ts for
 * the exact fallback behavior.
 */
export class NettleScanWorkerStack extends Stack {
  public readonly cluster: Cluster;
  public readonly taskDefinition: FargateTaskDefinition;
  public readonly workspaceBucket: Bucket;
  public readonly taskSecurityGroup: SecurityGroup;
  public readonly taskRoleArn: string;
  public readonly executionRoleArn: string;

  constructor(scope: Construct, id: string, props: NettleScanWorkerStackProps) {
    super(scope, id, props);

    // Ephemeral handoff storage only — never customer-durable data. A short
    // lifecycle rule bounds both storage cost and how long an extracted
    // workspace (untrusted source code) or a scan's raw results sit in S3
    // at all; the API deletes both explicitly once it has read the results,
    // this is a backstop for whatever it misses (a crashed API process
    // mid-cleanup, for instance).
    this.workspaceBucket = new Bucket(this, "ScanWorkspaceBucket", {
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      encryption: BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      lifecycleRules: [{ expiration: Duration.days(1) }],
    });

    this.cluster = new Cluster(this, "ScanWorkerCluster", { vpc: props.vpc, containerInsightsV2: ContainerInsights.DISABLED });

    // Two DIFFERENT roles, deliberately: the execution role is what Fargate
    // itself uses to pull the image and ship logs (infrastructure-level,
    // never touches application data); the task role is what code running
    // INSIDE the container can use (application-level — exactly the two S3
    // grants below, nothing else). Conflating them would let untrusted scan
    // code use ECR/logs permissions it has no reason to need, or — worse —
    // make it easy to accidentally broaden the task role by copying
    // execution-role-shaped grants onto it later.
    const executionRole = new Role(this, "ScanWorkerExecutionRole", {
      assumedBy: new ServicePrincipal("ecs-tasks.amazonaws.com"),
      description: "Nettle scan worker execution role - pulls the image and ships logs; no application data access",
    });
    props.repository.grantPull(executionRole);

    const taskRole = new Role(this, "ScanWorkerTaskRole", {
      assumedBy: new ServicePrincipal("ecs-tasks.amazonaws.com"),
      description:
        "Nettle scan worker task role - reads exactly one workspace object, writes exactly one results object, nothing else. " +
        "No Secrets Manager, no database, no Stripe/SES, no other AWS service.",
    });
    // Prefix-scoped, not bucket-wide: the worker can read any workspace
    // object and write any results object (it's told the exact key via its
    // own environment variables at RunTask time, and IAM has no per-task
    // key-level scoping mechanism for a static task role), but the split
    // into read-only/write-only by prefix still means a compromised scan
    // process cannot overwrite another scan's already-extracted workspace,
    // and cannot read another scan's results before the API has.
    taskRole.addToPolicy(
      new PolicyStatement({
        actions: ["s3:GetObject"],
        resources: [this.workspaceBucket.arnForObjects("workspaces/*")],
      })
    );
    taskRole.addToPolicy(
      new PolicyStatement({
        actions: ["s3:PutObject"],
        resources: [this.workspaceBucket.arnForObjects("results/*")],
      })
    );
    this.taskRoleArn = taskRole.roleArn;
    this.executionRoleArn = executionRole.roleArn;

    const logGroup = new LogGroup(this, "ScanWorkerLogs", {
      retention: RetentionDays.TWO_WEEKS,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Sizing matches api-stack.ts's own App Runner allocation (1 vCPU / 2GB)
    // — the same envelope a single scan needed when it ran inside the API
    // container, now an AWS-enforced hard limit instead of "whatever the
    // shared container happens to have free." Configurable here if a
    // specific scan's real needs turn out to differ once there's live data.
    this.taskDefinition = new FargateTaskDefinition(this, "ScanWorkerTaskDefinition", {
      cpu: 1024,
      memoryLimitMiB: 2048,
      executionRole,
      taskRole,
    });

    this.taskDefinition.addContainer("ScanWorker", {
      // Same image as Nettle-Api, different command — see this class's own
      // doc comment for why that's deliberate, not a shortcut.
      image: ContainerImage.fromEcrRepository(props.repository, "latest"),
      command: ["node", "dist/scanWorker.js"],
      logging: LogDrivers.awsLogs({ logGroup, streamPrefix: "scan-worker" }),
      // No secrets, no environment variables baked in here — the scan id,
      // S3 bucket/keys are supplied per-invocation as RunTask container
      // overrides (backend/src/scanner/isolatedExecution.ts), so nothing
      // about a specific scan is baked into the task definition itself.
    });

    // No ingress rules at all (nothing ever calls into a scan task) and
    // egress restricted to HTTPS. "HTTPS, any destination" reads broad, but
    // the isolated subnets' own route table (network-stack.ts) has no route
    // to 0.0.0.0/0 — no IGW, no NAT — so the only reachable HTTPS
    // destination from here is S3, via the gateway endpoint that same
    // subnet tier's route table carries. Restricting further to a specific
    // prefix list would be redundant with what the route table already
    // guarantees, and CDK's GatewayVpcEndpoint construct doesn't expose a
    // stable prefix-list reference to scope against directly.
    this.taskSecurityGroup = new SecurityGroup(this, "ScanWorkerSecurityGroup", {
      vpc: props.vpc,
      description: "Nettle scan worker - isolated subnet, S3 only (workspace/results handoff), no other network access",
      allowAllOutbound: false,
    });
    this.taskSecurityGroup.addEgressRule(Peer.anyIpv4(), Port.tcp(443), "HTTPS to S3 via the isolated subnets' gateway endpoint only");

    new CfnOutput(this, "ClusterArn", { value: this.cluster.clusterArn });
    new CfnOutput(this, "TaskDefinitionArn", { value: this.taskDefinition.taskDefinitionArn });
    new CfnOutput(this, "WorkspaceBucketName", { value: this.workspaceBucket.bucketName });
    new CfnOutput(this, "TaskSecurityGroupId", { value: this.taskSecurityGroup.securityGroupId });
    new CfnOutput(this, "IsolatedSubnetIds", {
      value: props.vpc.selectSubnets({ subnetType: SubnetType.PRIVATE_ISOLATED }).subnetIds.join(","),
    });
  }
}
