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
   * `secretArn` output), if that stack has actually been deployed. Optional
   * because deploying the API stack must not require RDS to exist first —
   * the backend still runs on SQLite either way (see
   * backend/src/db/postgres/README.md).
   */
  databaseSecretArn?: string;
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

    // maxSize is deliberately pinned at 1, not App Runner's own default
    // ceiling of 25 — every account, session, project, scan, and alert is
    // persisted to a local node:sqlite file on whichever single container
    // is running (see NETTLE_DB_PATH in backend/src/db/index.ts), with no
    // shared database or volume behind it. A second concurrent instance
    // would boot its own empty database, and requests would silently see
    // different data depending on which instance happened to serve them.
    // This resource exists so scaling is ready to enable the moment that's
    // no longer true (RDS, or any other shared store, replaces the
    // per-instance SQLite file) — raise maxSize then, not before.
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
