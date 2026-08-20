import { CfnOutput, Duration, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import { SecurityGroup, SubnetType } from "aws-cdk-lib/aws-ec2";
import {
  Cluster,
  FargateTaskDefinition,
  ContainerImage,
  LogDrivers,
  LinuxParameters,
  Capability,
} from "aws-cdk-lib/aws-ecs";
import { Repository, TagMutability } from "aws-cdk-lib/aws-ecr";
import { Role, ServicePrincipal, PolicyStatement, Effect } from "aws-cdk-lib/aws-iam";
import { Bucket, BlockPublicAccess, BucketEncryption } from "aws-cdk-lib/aws-s3";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
import type { Vpc } from "aws-cdk-lib/aws-ec2";
import type { Construct } from "constructs";

export interface NettleScannerStackProps extends StackProps {
  vpc: Vpc;
}

/**
 * The isolation boundary described in backend/src/scanner/ISOLATION.md,
 * expressed as infrastructure: a disposable ECS Fargate task per scan,
 * with its own dedicated IAM roles, its own security group (not the API's
 * connectorSecurityGroup — see network-stack.ts), its own S3 input bucket,
 * and its own log group. Nothing here is reachable from the internet
 * inbound, and nothing here can reach RDS: database-stack.ts's security
 * group only allows inbound from the API's connector security group, and
 * this stack never adds itself to that allow-list.
 *
 * Prepared, not deployed — same status as database-stack.ts. `cdk synth
 * Nettle-Scanner` produces a valid template; nothing has been applied to a
 * real AWS account. Deploying this (`cdk deploy Nettle-Scanner`), building
 * and pushing backend/Dockerfile.scanner-task to the ECR repo this stack
 * creates, and wiring its outputs into api-stack.ts (see
 * NETTLE_SCANNER_BACKEND and the NETTLE_SCANNER_* env vars documented in
 * jobs/fargateScanner.ts) are all still REQUIRES AWS CONFIGURATION steps
 * for whoever actually deploys this.
 */
export class NettleScannerStack extends Stack {
  public readonly clusterArn: string;
  public readonly taskDefinitionArn: string;
  public readonly taskDefinitionFamily: string;
  public readonly securityGroupId: string;
  public readonly subnetIds: string[];
  public readonly scanInputBucketName: string;
  public readonly scanInputBucketArn: string;
  public readonly repositoryArn: string;
  public readonly taskRoleArn: string;
  public readonly executionRoleArn: string;

  constructor(scope: Construct, id: string, props: NettleScannerStackProps) {
    super(scope, id, props);

    // Deliberately its own security group, not network-stack.ts's
    // connectorSecurityGroup the API uses. database-stack.ts's RDS
    // security group allows inbound only from that specific group by ID
    // (Peer.securityGroupId(props.apiSecurityGroup.securityGroupId)) — a
    // scan task running under this group has no network path to RDS at
    // all, by construction, with zero changes needed on the RDS side.
    //
    // Outbound is required: the task downloads its input from S3, clones
    // git repositories from customer-supplied (but scheme/host-restricted
    // — see scans.routes.ts's REPO_URL_PATTERN) URLs, and posts its result
    // back to the API's own callback endpoint. No inbound rules at all —
    // this task never accepts a connection from anything.
    const scannerSecurityGroup = new SecurityGroup(this, "ScannerSecurityGroup", {
      vpc: props.vpc,
      description: "Isolated Fargate scan task - outbound only (S3, git hosts, its own callback to the API). No inbound rules, no path to RDS.",
      allowAllOutbound: true,
    });

    const cluster = new Cluster(this, "ScannerCluster", {
      vpc: props.vpc,
      clusterName: "nettle-scanner",
      // No containerInsights - this cluster never runs a standing service
      // (see cost note below), so there's no continuous workload to
      // monitor; the per-task CloudWatch log group below is what actually
      // matters for debugging a specific scan.
    });

    // One S3 bucket, used only as the hand-off point for zip-upload scan
    // input (git-clone scans never touch it - see jobs/fargateScanner.ts).
    // autoDeleteObjects + a 1-day lifecycle expiration are defense in depth
    // on top of the explicit post-scan DeleteObjectCommand
    // fargateScanner.ts already issues - neither is the only thing
    // standing between a finished scan and its input still existing.
    const scanInputBucket = new Bucket(this, "ScanInputBucket", {
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      encryption: BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      lifecycleRules: [
        {
          id: "expire-scan-inputs",
          enabled: true,
          expiration: Duration.days(1),
          prefix: "uploads/",
        },
      ],
    });

    const logGroup = new LogGroup(this, "ScannerLogGroup", {
      logGroupName: "/nettle/scanner",
      retention: RetentionDays.TWO_WEEKS,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const repository = new Repository(this, "ScannerRepo", {
      repositoryName: "nettle-scanner",
      imageTagMutability: TagMutability.MUTABLE,
      removalPolicy: RemovalPolicy.DESTROY,
      emptyOnDelete: true,
    });

    // Execution role: what ECS itself uses to start the container (pull
    // the image, ship its logs). The running scan code never assumes this
    // role or sees its credentials - that's taskRole, below, which is
    // deliberately much narrower.
    const executionRole = new Role(this, "ScannerExecutionRole", {
      assumedBy: new ServicePrincipal("ecs-tasks.amazonaws.com"),
      description: "ECR pull + CloudWatch Logs write for the scanner task - nothing else",
    });
    repository.grantPull(executionRole);
    logGroup.grantWrite(executionRole);

    // Task role: what the running scan code itself can do. Deliberately
    // just S3 get/delete on the input prefix - no database credentials, no
    // Secrets Manager access, no other AWS API at all. This is the
    // concrete implementation of ISOLATION.md's "prefer the scanner
    // returning a controlled result over unrestricted database
    // credentials" - the task reports its result over an authenticated
    // HTTP callback (see routes/scanTaskCallback.routes.ts), not by
    // writing to the database directly.
    const taskRole = new Role(this, "ScannerTaskRole", {
      assumedBy: new ServicePrincipal("ecs-tasks.amazonaws.com"),
      description: "The running scan task's own permissions - S3 get/delete on the scan-input prefix only",
    });
    scanInputBucket.grantRead(taskRole, "uploads/*");
    scanInputBucket.grantDelete(taskRole, "uploads/*");

    // Belt-and-suspenders on top of security-group isolation and the
    // absence of any granted database permission: an explicit deny on the
    // one AWS API surface (Secrets Manager) that would otherwise let a
    // compromised task read whatever secret it could name, even one this
    // role was never granted access to via a resource policy elsewhere.
    taskRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.DENY,
        actions: ["secretsmanager:*"],
        resources: ["*"],
      })
    );

    const linuxParameters = new LinuxParameters(this, "ScannerLinuxParameters", {
      initProcessEnabled: true,
    });
    // Drop every Linux capability the container image doesn't need -
    // git/unzip/semgrep/node all run as an unprivileged process (see
    // Dockerfile.scanner-task's non-root USER) and none of them need any
    // elevated capability at all.
    linuxParameters.dropCapabilities(Capability.ALL);

    const taskDefinition = new FargateTaskDefinition(this, "ScannerTaskDef", {
      family: "nettle-scanner",
      cpu: 1024, // 1 vCPU
      memoryLimitMiB: 2048, // 2 GB
      ephemeralStorageGiB: 21, // Fargate's minimum - plenty for a single repo/zip well under safeExtraction.ts's 500MB cap
      executionRole,
      taskRole,
    });

    taskDefinition.addContainer("scanner", {
      containerName: "scanner",
      image: ContainerImage.fromEcrRepository(repository, "latest"),
      logging: LogDrivers.awsLogs({ streamPrefix: "scanner", logGroup }),
      readonlyRootFilesystem: true,
      user: "nettle",
      linuxParameters,
      // Slightly under the platform's own task-level timeout this stack's
      // consumer (fargateScanner.ts's NETTLE_SCANNER_TASK_TIMEOUT_MS,
      // default 10 minutes) expects - gives the container's own internal
      // watchdog (taskEntrypoint.ts's 9-minute TASK_WATCHDOG_MS) a chance
      // to post a failure callback before ECS just kills the task outright.
      stopTimeout: Duration.seconds(30),
      essential: true,
    });

    this.clusterArn = cluster.clusterArn;
    this.taskDefinitionArn = taskDefinition.taskDefinitionArn;
    this.taskDefinitionFamily = taskDefinition.family;
    this.securityGroupId = scannerSecurityGroup.securityGroupId;
    this.subnetIds = props.vpc.selectSubnets({ subnetType: SubnetType.PRIVATE_WITH_EGRESS }).subnetIds;
    this.scanInputBucketName = scanInputBucket.bucketName;
    this.scanInputBucketArn = scanInputBucket.bucketArn;
    this.repositoryArn = repository.repositoryArn;
    this.taskRoleArn = taskRole.roleArn;
    this.executionRoleArn = executionRole.roleArn;

    new CfnOutput(this, "ClusterArn", { value: cluster.clusterArn });
    new CfnOutput(this, "TaskDefinitionArn", { value: taskDefinition.taskDefinitionArn });
    new CfnOutput(this, "TaskDefinitionFamily", { value: taskDefinition.family });
    new CfnOutput(this, "SecurityGroupId", { value: scannerSecurityGroup.securityGroupId });
    new CfnOutput(this, "SubnetIds", { value: this.subnetIds.join(",") });
    new CfnOutput(this, "ScanInputBucketName", { value: scanInputBucket.bucketName });
    new CfnOutput(this, "ScannerRepositoryUri", { value: repository.repositoryUri });
    new CfnOutput(this, "ScannerRepositoryArn", { value: repository.repositoryArn });
  }
}
