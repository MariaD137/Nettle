import { CfnOutput, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import { Repository, TagMutability } from "aws-cdk-lib/aws-ecr";
import { CfnVpcConnector, CfnService, CfnAutoScalingConfiguration } from "aws-cdk-lib/aws-apprunner";
import { Role, ServicePrincipal, ManagedPolicy, PolicyStatement } from "aws-cdk-lib/aws-iam";
import { Secret } from "aws-cdk-lib/aws-secretsmanager";
import type { Vpc, SecurityGroup } from "aws-cdk-lib/aws-ec2";
import type { Construct } from "constructs";

export interface NettleApiStackProps extends StackProps {
  vpc: Vpc;
  connectorSecurityGroup: SecurityGroup;
  /**
   * ARN of the RDS-generated credentials secret (database-stack.ts's
   * `secretArn` output) and the instance's endpoint hostname
   * (database-stack.ts's `instanceEndpoint` output), if that stack has
   * actually been deployed. Both optional at the type level because
   * deploying the API stack must not *require* editing this file first —
   * but the backend has no SQLite fallback any more (see
   * backend/src/db/postgres/README.md): it needs a real PostgreSQL
   * connection to start at all. Passing both is what wires the database
   * into the service's PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE
   * environment variables below — omit them and the deployed service will
   * fail to boot with a clear "no PostgreSQL connection configured" error
   * rather than silently starting broken.
   *
   * Deliberately NOT reading host/port back out of the secret itself: an
   * RDS `SecretTargetAttachment` (which this repo's database-stack.ts does
   * not configure) is what AWS documents as populating those fields into
   * the secret's own JSON at runtime, and confirming that actually
   * happened requires a live AWS account to observe — not something this
   * repository can verify for itself. The endpoint address CDK already
   * knows deterministically at synth time (`instance.dbInstanceEndpointAddress`)
   * is used instead, and the port is PostgreSQL's fixed default (RDS
   * doesn't override it here) rather than pulled from anywhere secret.
   *
   * REQUIRES AWS CONFIGURATION: these values only exist once a human has
   * actually deployed Nettle-Database (`cdk deploy Nettle-Database`) in a
   * real AWS account and copied its outputs here (or into bin/app.ts) —
   * nothing in this repository does that on its own.
   */
  databaseSecretArn?: string;
  databaseEndpointAddress?: string;
}

/**
 * The name of a Secrets Manager secret that must already exist in the
 * target AWS account before this stack is deployed — created and
 * populated by a human (see AWS_GITHUB_DEPLOYMENT.md), never by this CDK
 * code or by Claude. Expected to be a single JSON secret with these keys:
 * stripeSecretKey, stripeWebhookSecret, stripePriceTier1, stripePriceTier2,
 * nettleTokenEncryptionKey, nettleWebhookSecret, cronSecret, smtpUser,
 * smtpPass, twilioAccountSid, twilioAuthToken.
 */
const APP_SECRETS_NAME = "nettle/app-secrets";

/**
 * The whole Tier 1+2 API as a single App Runner service, pulling its
 * secrets from AWS Secrets Manager at container startup rather than having
 * them baked into the image or the CDK source (see APP_SECRETS_NAME
 * above). Still SQLite-backed today, not RDS-backed — see
 * backend/src/db/postgres/README.md — so maxSize below stays pinned at 1
 * regardless of whether database-stack.ts has been deployed.
 */
export class NettleApiStack extends Stack {
  public readonly serviceUrl: string;
  public readonly repositoryArn: string;

  constructor(scope: Construct, id: string, props: NettleApiStackProps) {
    super(scope, id, props);

    const repository = new Repository(this, "ScanApiRepo", {
      repositoryName: "nettle-api",
      imageTagMutability: TagMutability.MUTABLE, // App Runner auto-deploys by watching the :latest tag
      removalPolicy: RemovalPolicy.DESTROY,
      emptyOnDelete: true,
    });

    const ecrAccessRole = new Role(this, "ApiEcrAccessRole", {
      assumedBy: new ServicePrincipal("build.apprunner.amazonaws.com"),
      managedPolicies: [ManagedPolicy.fromAwsManagedPolicyName("AmazonEC2ContainerRegistryReadOnly")],
    });

    // References a secret that must already exist — this stack never
    // creates or populates a secret value itself (see APP_SECRETS_NAME).
    const appSecrets = Secret.fromSecretNameV2(this, "AppSecrets", APP_SECRETS_NAME);

    // The instance role is what the running container uses to fetch the
    // runtimeEnvironmentSecrets values below at startup — separate from
    // ecrAccessRole above, which is only used to pull the image itself.
    // Scoped to exactly the secrets this service actually needs, nothing
    // account-wide.
    const instanceRole = new Role(this, "ApiInstanceRole", {
      assumedBy: new ServicePrincipal("tasks.apprunner.amazonaws.com"),
    });
    instanceRole.addToPolicy(
      new PolicyStatement({
        actions: ["secretsmanager:GetSecretValue"],
        resources: [
          appSecrets.secretArn,
          ...(props.databaseSecretArn ? [props.databaseSecretArn] : []),
        ],
      })
    );

    const vpcConnector = new CfnVpcConnector(this, "ApiVpcConnector", {
      subnets: props.vpc.privateSubnets.map((s) => s.subnetId),
      securityGroups: [props.connectorSecurityGroup.securityGroupId],
      vpcConnectorName: "nettle-api-connector",
    });

    // maxSize is still pinned at 1, not App Runner's own default ceiling of
    // 25. The backend's data layer is PostgreSQL now (a real shared store,
    // not a per-instance file — see backend/src/db/postgres/README.md), so
    // the original reason for this ceiling (every instance would otherwise
    // have booted its own empty SQLite database) no longer applies. It's
    // left at 1 anyway because multi-instance scaling has never actually
    // been exercised against this app — session/rate-limit state that
    // still lives in each process's memory (see backend/README.md's known
    // gaps) hasn't been verified safe across concurrent instances. Raise
    // this deliberately, once, after that's been checked — not as a side
    // effect of the database migration.
    const autoScaling = new CfnAutoScalingConfiguration(this, "ApiAutoScaling", {
      autoScalingConfigurationName: "nettle-api-autoscaling",
      minSize: 1,
      maxSize: 1,
      maxConcurrency: 80,
    });

    // References a specific key within the JSON secret — the well-known
    // App Runner/ECS pattern for "one field of a multi-field secret," not
    // a made-up format. jsonKey values match APP_SECRETS_NAME's doc comment.
    const secretRef = (jsonKey: string) => `${appSecrets.secretArn}:${jsonKey}::`;

    // Same one-field-per-env-var pattern, against the RDS-generated
    // credentials secret instead of appSecrets — but only for the two
    // fields actually inside it. database-stack.ts creates the secret via
    // `Credentials.fromGeneratedSecret("nettle_admin")` with no `dbname`
    // option, so its JSON template is just `{"username": "nettle_admin"}`
    // plus the generated `password` key — verified directly from
    // aws-cdk-lib's source (Credentials.fromGeneratedSecret /
    // DatabaseSecret), not assumed. It does NOT contain host/port/dbname:
    // those would only be added by an RDS `SecretTargetAttachment`
    // rotation, which this stack doesn't configure, and confirming one
    // happened would need a live AWS account to observe. So host/port/
    // dbname are sourced from values CDK already knows for certain instead:
    // the endpoint address is a real CloudFormation attribute reference
    // (props.databaseEndpointAddress, from database-stack.ts's
    // `instanceEndpoint` output), the port is PostgreSQL's fixed default
    // (database-stack.ts never overrides it), and the database name is the
    // literal "nettle" database-stack.ts passes as `databaseName` — none of
    // these three are secret values.
    const dbSecretRef = (jsonKey: string) => `${props.databaseSecretArn}:${jsonKey}::`;
    const databaseConfigured = Boolean(props.databaseSecretArn && props.databaseEndpointAddress);
    const databaseEnvVars = databaseConfigured
      ? [
          { name: "PGHOST", value: props.databaseEndpointAddress! },
          { name: "PGPORT", value: "5432" },
          { name: "PGDATABASE", value: "nettle" },
        ]
      : [];
    const databaseEnvSecrets = databaseConfigured
      ? [
          { name: "PGUSER", value: dbSecretRef("username") },
          { name: "PGPASSWORD", value: dbSecretRef("password") },
        ]
      : [];

    const service = new CfnService(this, "ApiService", {
      serviceName: "nettle-api",
      autoScalingConfigurationArn: autoScaling.attrAutoScalingConfigurationArn,
      sourceConfiguration: {
        autoDeploymentsEnabled: true,
        authenticationConfiguration: {
          accessRoleArn: ecrAccessRole.roleArn,
        },
        imageRepository: {
          imageIdentifier: `${repository.repositoryUri}:latest`,
          imageRepositoryType: "ECR",
          imageConfiguration: {
            port: "8080",
            runtimeEnvironmentVariables: [
              { name: "NODE_ENV", value: "production" },
              { name: "PORT", value: "8080" },
              ...databaseEnvVars,
            ],
            // Every value here comes from Secrets Manager, never from CDK
            // source or this repository — see APP_SECRETS_NAME's doc
            // comment for the secret's expected shape and
            // AWS_GITHUB_DEPLOYMENT.md for who creates it and how.
            runtimeEnvironmentSecrets: [
              { name: "STRIPE_SECRET_KEY", value: secretRef("stripeSecretKey") },
              { name: "STRIPE_WEBHOOK_SECRET", value: secretRef("stripeWebhookSecret") },
              { name: "STRIPE_PRICE_TIER1", value: secretRef("stripePriceTier1") },
              { name: "STRIPE_PRICE_TIER2", value: secretRef("stripePriceTier2") },
              { name: "NETTLE_TOKEN_ENCRYPTION_KEY", value: secretRef("nettleTokenEncryptionKey") },
              { name: "NETTLE_WEBHOOK_SECRET", value: secretRef("nettleWebhookSecret") },
              { name: "CRON_SECRET", value: secretRef("cronSecret") },
              { name: "SMTP_USER", value: secretRef("smtpUser") },
              { name: "SMTP_PASS", value: secretRef("smtpPass") },
              { name: "TWILIO_ACCOUNT_SID", value: secretRef("twilioAccountSid") },
              { name: "TWILIO_AUTH_TOKEN", value: secretRef("twilioAuthToken") },
              ...databaseEnvSecrets,
            ],
          },
        },
      },
      instanceConfiguration: {
        cpu: "0.25 vCPU",
        memory: "0.5 GB",
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
    this.repositoryArn = repository.repositoryArn;

    new CfnOutput(this, "RepositoryUri", { value: repository.repositoryUri });
    new CfnOutput(this, "ServiceUrl", { value: `https://${service.attrServiceUrl}` });
  }
}
