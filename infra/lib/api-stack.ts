import { CfnOutput, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import { Repository, TagMutability } from "aws-cdk-lib/aws-ecr";
import { CfnVpcConnector, CfnService, CfnAutoScalingConfiguration } from "aws-cdk-lib/aws-apprunner";
import { Role, ServicePrincipal, ManagedPolicy } from "aws-cdk-lib/aws-iam";
import type { Vpc, SecurityGroup } from "aws-cdk-lib/aws-ec2";
import type { Construct } from "constructs";

export interface NettleApiStackProps extends StackProps {
  vpc: Vpc;
  connectorSecurityGroup: SecurityGroup;
}

/**
 * The whole Tier 1 API as a single App Runner service. No RDS, no Cognito —
 * this is a stateless "upload code, get a report back" service with no
 * accounts yet. Adding a database is the right move once there's a reason
 * for one (paying customers, saved scan history), not before.
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

    const vpcConnector = new CfnVpcConnector(this, "ApiVpcConnector", {
      subnets: props.vpc.isolatedSubnets.map((s) => s.subnetId),
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
          },
        },
      },
      instanceConfiguration: {
        cpu: "0.25 vCPU",
        memory: "0.5 GB",
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
