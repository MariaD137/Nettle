import { CfnOutput, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import { Repository, TagMutability } from "aws-cdk-lib/aws-ecr";
import { CfnVpcConnector, CfnService } from "aws-cdk-lib/aws-apprunner";
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

    const service = new CfnService(this, "ApiService", {
      serviceName: "nettle-api",
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
