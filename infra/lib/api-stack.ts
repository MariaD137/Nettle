import { CfnOutput, RemovalPolicy, SecretValue, Stack, type StackProps } from "aws-cdk-lib";
import type { IRepository } from "aws-cdk-lib/aws-ecr";
import { CfnVpcConnector, CfnService } from "aws-cdk-lib/aws-apprunner";
import { Role, ServicePrincipal, ManagedPolicy, PolicyStatement } from "aws-cdk-lib/aws-iam";
import { SubnetType, type Vpc, type SecurityGroup } from "aws-cdk-lib/aws-ec2";
import { Secret, type ISecret } from "aws-cdk-lib/aws-secretsmanager";
import type { Construct } from "constructs";

export interface NettleApiStackProps extends StackProps {
  vpc: Vpc;
  connectorSecurityGroup: SecurityGroup;
  /** Secrets Manager secret created with the RDS instance. */
  databaseSecret: ISecret;
  databaseEndpoint: string;
  /**
   * The ECR repository the container image lives in, created in its own
   * stack (see ecr-stack.ts) rather than here — see that file for why: this
   * stack's App Runner service needs an image to already exist in the repo
   * at creation time, so the repo cannot be created in the same deploy
   * attempt as the service that reads from it.
   */
  repository: IRepository;
  /**
   * Set to deploy a second, independent environment (e.g. "staging") off
   * this same stack definition rather than duplicating it. Left undefined,
   * every physical resource name below is IDENTICAL to what this stack
   * created before this parameter existed — the production instantiation in
   * bin/app.ts omits it deliberately, so this change cannot rename/replace
   * any resource CloudFormation already manages for production. When set,
   * it suffixes the handful of physical names that must be unique
   * account-wide (Secrets Manager secret name, VPC connector name, App
   * Runner service name) so a second instantiation of this stack doesn't
   * collide with the first.
   */
  stageName?: string;
  /**
   * Which ECR image tag this service tracks. Defaults to "latest" (what
   * production has always used — see backend-deploy.yml, which pushes
   * :latest and relies on autoDeploymentsEnabled below to pick it up).
   * A staging instantiation passes "staging" to track the tag
   * backend-deploy-staging.yml already pushes on every merge to `develop`
   * (that workflow has pushed :staging since before this stack existed to
   * consume it — see that file's history).
   */
  imageTag?: string;
  /**
   * scan-worker-stack.ts's outputs, wired in so the API can actually
   * dispatch a scan to an isolated Fargate task (ecs:RunTask) instead of
   * running it in-process. Optional and additive: omitted, this stack's
   * ApiInstanceRole/ApiService are unchanged from before this prop existed
   * — the backend's own isolatedExecution.ts falls back to in-process
   * execution when these env vars aren't present, so an instantiation
   * without this (or a stale deploy of this stack from before it existed)
   * keeps working, just without the isolation.
   */
  scanWorker?: {
    clusterArn: string;
    taskDefinitionArn: string;
    /** Comma-separated — App Runner's runtimeEnvironmentVariables are flat strings, not lists. */
    subnetIds: string;
    securityGroupId: string;
    workspaceBucketName: string;
    taskRoleArn: string;
    executionRoleArn: string;
  };
}

/**
 * The Tier 1/Tier 2 API as a single App Runner service.
 *
 * Configuration is split deliberately:
 *   runtimeEnvironmentVariables — non-sensitive values, visible in the console
 *   runtimeEnvironmentSecrets   — Secrets Manager ARNs, resolved by App Runner
 *                                 at start-up and never rendered into the
 *                                 template, the repository or a log line
 *
 * No real secret VALUE appears in this file. The application secret below is
 * created with placeholder ("unset") values in the expected JSON shape: CDK
 * provisions the container, an operator populates it with real values once,
 * out of band. It is deliberately NOT created truly empty (no
 * generateSecretString/secretObjectValue at all) — that was this stack's
 * original design, on the reasoning that the service should fail at the
 * first Stripe charge rather than start with a fake key. In practice a
 * secret created that way holds a bare random string, not JSON, and
 * runtimeEnvironmentSecrets below resolves each variable via App Runner's
 * `<arn>:<jsonKey>::` syntax, which requires real JSON — so the service
 * failed to start at all, silently, with no application-level logs ever
 * produced, which is strictly worse than "fails at the first charge."
 */
export class NettleApiStack extends Stack {
  public readonly serviceUrl: string;
  public readonly serviceArn: string;
  public readonly repositoryArn: string;

  constructor(scope: Construct, id: string, props: NettleApiStackProps) {
    super(scope, id, props);

    const repository = props.repository;
    // Every physical name below that must be unique account-wide gets this
    // suffix — "" for the production instantiation (props.stageName
    // omitted), so production's resource names are byte-for-byte identical
    // to what they were before stageName existed. See the prop's own
    // comment on why that matters.
    const suffix = props.stageName ? `-${props.stageName}` : "";
    const imageTag = props.imageTag ?? "latest";

    /**
     * Application secrets, as opposed to the database credentials RDS
     * generates. Created with placeholder values under the expected keys so
     * an operator knows exactly what to fill in:
     *
     *   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
     *   STRIPE_PRICE_BUILD, STRIPE_PRICE_PROTECT
     *
     * Populate with:
     *   aws secretsmanager put-secret-value \
     *     --secret-id nettle/application{suffix} \
     *     --secret-string '{"STRIPE_SECRET_KEY":"...", ...}'
     *
     * A staging instantiation gets its OWN secret (nettle/application-staging),
     * never the production one — staging is meant to be populated with
     * Stripe test-mode keys, and sharing the production secret would mean a
     * staging deploy either can't be configured independently or, worse,
     * ends up pointed at live Stripe keys.
     *
     * secretObjectValue below gives the secret real JSON structure at
     * creation, with placeholder (non-functional) values — not just
     * "empty". Without it, CDK's Secret construct defaults to
     * `generateSecretString: {}`, which produces a bare random string, not
     * JSON. runtimeEnvironmentSecrets below references each key with App
     * Runner's `<arn>:<jsonKey>::` syntax, which requires the secret to
     * actually contain that JSON key — against a non-JSON secret, App
     * Runner fails to resolve the reference during its own secret-resolution
     * step, before the container is ever started. That failure produces no
     * application-level logs at all (nothing ever ran), surfaces only as an
     * opaque CREATE_FAILED/NotStabilized on the service resource, and is
     * exactly the failure this comment exists to prevent recurring.
     */
    const appSecret = new Secret(this, "ApplicationSecret", {
      secretName: `nettle/application${suffix}`,
      description:
        "Nettle application secrets. Keys: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, " +
        "STRIPE_PRICE_BUILD, STRIPE_PRICE_PROTECT. Populate out of band; never in source control.",
      removalPolicy: RemovalPolicy.RETAIN,
      secretObjectValue: {
        STRIPE_SECRET_KEY: SecretValue.unsafePlainText("unset"),
        STRIPE_WEBHOOK_SECRET: SecretValue.unsafePlainText("unset"),
        STRIPE_PRICE_BUILD: SecretValue.unsafePlainText("unset"),
        STRIPE_PRICE_PROTECT: SecretValue.unsafePlainText("unset"),
      },
    });

    const ecrAccessRole = new Role(this, "ApiEcrAccessRole", {
      assumedBy: new ServicePrincipal("build.apprunner.amazonaws.com"),
      managedPolicies: [ManagedPolicy.fromAwsManagedPolicyName("AmazonEC2ContainerRegistryReadOnly")],
    });

    // The running task's identity. It needs to read exactly two secrets and
    // nothing else, so the grants are per-secret rather than a wildcard policy.
    const instanceRole = new Role(this, "ApiInstanceRole", {
      assumedBy: new ServicePrincipal("tasks.apprunner.amazonaws.com"),
      description: "Nettle API runtime role - reads its own secrets, sends transactional email, nothing more",
    });
    props.databaseSecret.grantRead(instanceRole);
    appSecret.grantRead(instanceRole);

    // notifications/email.ts (password-reset and organization-invitation
    // delivery) sends through SES using this role's credentials via the
    // SDK's default provider chain — no access key is ever configured.
    // ses:SendEmail/SendRawEmail only; no permission to manage identities,
    // read other mail, or touch anything else in the account. Scoped to
    // this account/region rather than "*" — SES resources are addressed by
    // ARN pattern (identity, configuration set), not by a resource this
    // role owns, so a full wildcard would be needed to send at all;
    // account+region scoping is what keeps this from also being able to
    // send AS a completely different verified identity if one is ever
    // added to this account for an unrelated purpose.
    instanceRole.addToPolicy(
      new PolicyStatement({
        actions: ["ses:SendEmail", "ses:SendRawEmail"],
        resources: [`arn:aws:ses:${this.region}:${this.account}:identity/*`],
      })
    );

    // scanner/isolatedExecution.ts's dispatch to the isolated scan worker
    // (scan-worker-stack.ts) — every grant here is scoped to that one task
    // definition/cluster/bucket, never account-wide. Absent when
    // props.scanWorker isn't provided, in which case the API has none of
    // these permissions at all and isolatedExecution.ts's own
    // isConfigured() check (driven by the env vars below, also absent)
    // correctly falls back to in-process execution rather than failing on
    // an AccessDenied.
    if (props.scanWorker) {
      const sw = props.scanWorker;
      instanceRole.addToPolicy(
        new PolicyStatement({
          actions: ["ecs:RunTask"],
          resources: [sw.taskDefinitionArn],
          conditions: { ArnEquals: { "ecs:cluster": sw.clusterArn } },
        })
      );
      instanceRole.addToPolicy(
        new PolicyStatement({
          actions: ["ecs:DescribeTasks", "ecs:StopTask"],
          // Individual task ARNs are only known once RunTask returns one;
          // scoped to "any task in this one cluster" via the resource
          // pattern, which is as tight as a static IAM policy can get for
          // actions on resources created dynamically at runtime.
          resources: [`arn:aws:ecs:${this.region}:${this.account}:task/*`],
          conditions: { ArnEquals: { "ecs:cluster": sw.clusterArn } },
        })
      );
      // ecs:RunTask requires the caller to be able to pass the task's own
      // roles to ECS — scoped to exactly these two role ARNs, not "*".
      instanceRole.addToPolicy(
        new PolicyStatement({
          actions: ["iam:PassRole"],
          resources: [sw.taskRoleArn, sw.executionRoleArn],
        })
      );
      // Mirror image of the task role's own two grants (scan-worker-stack.ts):
      // the API writes the workspace the task will read, and reads the
      // results the task wrote — the reverse direction of the task's own
      // permissions, never both directions on the same prefix for either
      // side.
      instanceRole.addToPolicy(
        new PolicyStatement({
          actions: ["s3:PutObject", "s3:DeleteObject"],
          resources: [`arn:aws:s3:::${sw.workspaceBucketName}/workspaces/*`],
        })
      );
      instanceRole.addToPolicy(
        new PolicyStatement({
          actions: ["s3:GetObject", "s3:DeleteObject"],
          resources: [`arn:aws:s3:::${sw.workspaceBucketName}/results/*`],
        })
      );
    }

    const vpcConnector = new CfnVpcConnector(this, "ApiVpcConnector", {
      // The egress subnets, not the isolated ones: the service needs a route
      // to Stripe and the git hosts through the NAT gateway.
      subnets: props.vpc.selectSubnets({ subnetType: SubnetType.PRIVATE_WITH_EGRESS }).subnetIds,
      securityGroups: [props.connectorSecurityGroup.securityGroupId],
      vpcConnectorName: `nettle-api-connector${suffix}`,
    });

    const service = new CfnService(this, "ApiService", {
      serviceName: `nettle-api${suffix}`,
      sourceConfiguration: {
        autoDeploymentsEnabled: true,
        authenticationConfiguration: { accessRoleArn: ecrAccessRole.roleArn },
        imageRepository: {
          // imageTag defaults to "latest" (production, unchanged). A staging
          // instantiation passes "staging" — this is what makes the service
          // actually watch the tag backend-deploy-staging.yml has been
          // pushing on every merge to `develop`, closing the gap where that
          // workflow ran but nothing ever consumed its output.
          imageIdentifier: `${repository.repositoryUri}:${imageTag}`,
          imageRepositoryType: "ECR",
          imageConfiguration: {
            port: "8080",
            runtimeEnvironmentVariables: [
              // NODE_ENV stays "production" even for staging — this is the
              // app's own operating mode (which guards its startup requires,
              // e.g. db/index.ts's DATABASE_URL check), not an indicator of
              // which physical environment it's running in. Staging should
              // behave like production code, against a separate database
              // and separate Stripe test-mode keys.
              { name: "NODE_ENV", value: "production" },
              { name: "PORT", value: "8080" },
              // Non-sensitive connection parts only. The credentials
              // themselves go through runtimeEnvironmentSecrets below — see
              // that block's comment for why they can't be combined into a
              // single composite DATABASE_URL here.
              { name: "DB_HOST", value: props.databaseEndpoint },
              { name: "DB_PORT", value: "5432" },
              { name: "DB_NAME", value: "nettle" },
              // Read by scanner/isolatedExecution.ts's isConfigured() — all
              // five present is what switches scan execution from
              // in-process to the isolated Fargate task. Omitted entirely
              // (not even empty strings) when props.scanWorker isn't
              // provided, so isConfigured() sees them as genuinely absent
              // rather than empty-but-present.
              ...(props.scanWorker
                ? [
                    { name: "SCAN_ECS_CLUSTER_ARN", value: props.scanWorker.clusterArn },
                    { name: "SCAN_ECS_TASK_DEFINITION_ARN", value: props.scanWorker.taskDefinitionArn },
                    { name: "SCAN_ECS_SUBNET_IDS", value: props.scanWorker.subnetIds },
                    { name: "SCAN_ECS_SECURITY_GROUP_ID", value: props.scanWorker.securityGroupId },
                    { name: "SCAN_WORKSPACE_BUCKET_NAME", value: props.scanWorker.workspaceBucketName },
                  ]
                : []),
            ],
            runtimeEnvironmentSecrets: [
              // App Runner resolves these itself, inside the running
              // container, from the RDS-generated secret's own "username"/
              // "password" JSON keys — never stored in this template, in App
              // Runner's own service configuration, or anywhere DescribeService
              // or the console would surface it. backend/src/db/index.ts
              // assembles the actual connection string from these plus the
              // DB_HOST/DB_PORT/DB_NAME above once it's running.
              //
              // A composite DATABASE_URL can't go through this same
              // mechanism: each entry here substitutes one whole env var
              // with one whole secret JSON key's value, so there's no way
              // to interpolate a "postgresql://" prefix and a hostname
              // around two separate secret fields — hence two entries
              // instead of one.
              { name: "DB_USERNAME", value: `${props.databaseSecret.secretArn}:username::` },
              { name: "DB_PASSWORD", value: `${props.databaseSecret.secretArn}:password::` },
              { name: "STRIPE_SECRET_KEY", value: `${appSecret.secretArn}:STRIPE_SECRET_KEY::` },
              { name: "STRIPE_WEBHOOK_SECRET", value: `${appSecret.secretArn}:STRIPE_WEBHOOK_SECRET::` },
              { name: "STRIPE_PRICE_BUILD", value: `${appSecret.secretArn}:STRIPE_PRICE_BUILD::` },
              { name: "STRIPE_PRICE_PROTECT", value: `${appSecret.secretArn}:STRIPE_PRICE_PROTECT::` },
            ],
          },
        },
      },
      instanceConfiguration: {
        cpu: "1 vCPU",
        // Raised from 0.25 vCPU / 0.5 GB. Semgrep is a Python process working
        // over an extraction of up to 500 MB, and the previous allocation was
        // below what a single large scan needs. This is sizing for the work
        // that exists today; it is not a substitute for moving scanning off
        // the request path, which remains outstanding.
        memory: "2 GB",
        instanceRoleArn: instanceRole.roleArn,
      },
      networkConfiguration: {
        egressConfiguration: {
          egressType: "VPC",
          vpcConnectorArn: vpcConnector.attrVpcConnectorArn,
        },
      },
      healthCheckConfiguration: {
        protocol: "HTTP",
        path: "/health",
        interval: 10,
        timeout: 5,
        healthyThreshold: 1,
        unhealthyThreshold: 5,
      },
    });

    this.serviceUrl = service.attrServiceUrl;
    this.serviceArn = service.attrServiceArn;
    this.repositoryArn = repository.repositoryArn;

    new CfnOutput(this, "ServiceUrl", { value: `https://${service.attrServiceUrl}` });
    new CfnOutput(this, "ApplicationSecretArn", { value: appSecret.secretArn });
  }
}
