import { CfnOutput, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import type { IRepository } from "aws-cdk-lib/aws-ecr";
import { CfnVpcConnector, CfnService } from "aws-cdk-lib/aws-apprunner";
import { Role, ServicePrincipal, ManagedPolicy } from "aws-cdk-lib/aws-iam";
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
 * No secret VALUE appears in this file. The application secret below is
 * created empty: CDK provisions the container, an operator populates it once,
 * out of band. Generating a placeholder Stripe key would be worse than an
 * empty one, because the service would start and fail confusingly at the first
 * charge rather than at boot.
 */
export class NettleApiStack extends Stack {
  public readonly serviceUrl: string;
  public readonly repositoryArn: string;

  constructor(scope: Construct, id: string, props: NettleApiStackProps) {
    super(scope, id, props);

    const repository = props.repository;

    /**
     * Application secrets, as opposed to the database credentials RDS
     * generates. Created as an empty shell with the expected keys documented
     * so an operator knows exactly what to fill in:
     *
     *   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
     *   STRIPE_PRICE_TIER1, STRIPE_PRICE_TIER2
     *
     * Populate with:
     *   aws secretsmanager put-secret-value \
     *     --secret-id nettle/application \
     *     --secret-string '{"STRIPE_SECRET_KEY":"...", ...}'
     */
    const appSecret = new Secret(this, "ApplicationSecret", {
      secretName: "nettle/application",
      description:
        "Nettle application secrets. Keys: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, " +
        "STRIPE_PRICE_TIER1, STRIPE_PRICE_TIER2. Populate out of band; never in source control.",
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const ecrAccessRole = new Role(this, "ApiEcrAccessRole", {
      assumedBy: new ServicePrincipal("build.apprunner.amazonaws.com"),
      managedPolicies: [ManagedPolicy.fromAwsManagedPolicyName("AmazonEC2ContainerRegistryReadOnly")],
    });

    // The running task's identity. It needs to read exactly two secrets and
    // nothing else, so the grants are per-secret rather than a wildcard policy.
    const instanceRole = new Role(this, "ApiInstanceRole", {
      assumedBy: new ServicePrincipal("tasks.apprunner.amazonaws.com"),
      description: "Nettle API runtime role - reads its own secrets, nothing more",
    });
    props.databaseSecret.grantRead(instanceRole);
    appSecret.grantRead(instanceRole);

    const vpcConnector = new CfnVpcConnector(this, "ApiVpcConnector", {
      // The egress subnets, not the isolated ones: the service needs a route
      // to Stripe and the git hosts through the NAT gateway.
      subnets: props.vpc.selectSubnets({ subnetType: SubnetType.PRIVATE_WITH_EGRESS }).subnetIds,
      securityGroups: [props.connectorSecurityGroup.securityGroupId],
      vpcConnectorName: "nettle-api-connector",
    });

    const service = new CfnService(this, "ApiService", {
      serviceName: "nettle-api",
      sourceConfiguration: {
        autoDeploymentsEnabled: true,
        authenticationConfiguration: { accessRoleArn: ecrAccessRole.roleArn },
        imageRepository: {
          imageIdentifier: `${repository.repositoryUri}:latest`,
          imageRepositoryType: "ECR",
          imageConfiguration: {
            port: "8080",
            runtimeEnvironmentVariables: [
              { name: "NODE_ENV", value: "production" },
              { name: "PORT", value: "8080" },
              // Assembled from the RDS secret's discrete fields rather than
              // stored as a URL, so the password never exists as a separate
              // copy that could drift from the one RDS rotates.
              {
                name: "DATABASE_URL",
                value: [
                  "postgresql://",
                  props.databaseSecret.secretValueFromJson("username").unsafeUnwrap(),
                  ":",
                  props.databaseSecret.secretValueFromJson("password").unsafeUnwrap(),
                  "@",
                  props.databaseEndpoint,
                  ":5432/nettle",
                ].join(""),
              },
            ],
            runtimeEnvironmentSecrets: [
              { name: "STRIPE_SECRET_KEY", value: `${appSecret.secretArn}:STRIPE_SECRET_KEY::` },
              { name: "STRIPE_WEBHOOK_SECRET", value: `${appSecret.secretArn}:STRIPE_WEBHOOK_SECRET::` },
              { name: "STRIPE_PRICE_TIER1", value: `${appSecret.secretArn}:STRIPE_PRICE_TIER1::` },
              { name: "STRIPE_PRICE_TIER2", value: `${appSecret.secretArn}:STRIPE_PRICE_TIER2::` },
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
    this.repositoryArn = repository.repositoryArn;

    new CfnOutput(this, "ServiceUrl", { value: `https://${service.attrServiceUrl}` });
    new CfnOutput(this, "ApplicationSecretArn", { value: appSecret.secretArn });
  }
}
