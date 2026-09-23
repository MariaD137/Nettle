import { CfnOutput, Stack, type StackProps } from "aws-cdk-lib";
import { Vpc, SubnetType, SecurityGroup, Peer, Port, InterfaceVpcEndpointAwsService, GatewayVpcEndpointAwsService } from "aws-cdk-lib/aws-ec2";
import type { Construct } from "constructs";

/**
 * Network layout.
 *
 * This stack previously had zero NAT gateways and isolated subnets only,
 * which was correct when Tier 1 had no data store and made no outbound calls.
 * The application has since grown hard dependencies that live on the public
 * internet, and App Runner with `egressType: "VPC"` routes *all* outbound
 * traffic through this VPC — so with no NAT there was no route and those
 * calls simply could not complete:
 *
 *   - api.stripe.com          — checkout sessions, subscription cancellation
 *   - github.com / gitlab.com / bitbucket.org — /api/scans/repo `git clone`
 *
 * Neither has a VPC endpoint, because neither is an AWS service. NAT is
 * therefore required, not a convenience. It is kept to the minimum that
 * works:
 *
 *   - ONE NAT gateway, not one per AZ. A second would double the hourly cost
 *     to buy AZ-redundancy for outbound calls that are already retryable and
 *     non-critical to serving a request. Revisit if outbound becomes
 *     request-critical.
 *   - Cost: roughly $32/month for the gateway plus ~$0.045/GB processed
 *     (us-east-1). Scan traffic is git clones and Stripe API calls, so the
 *     data volume is small.
 *
 * Three tiers of subnet:
 *   public            — holds only the NAT gateway
 *   private-egress    — the App Runner VPC connector; can reach the internet
 *                       via NAT, cannot be reached from it
 *   isolated          — the database; no route to or from the internet at all
 *
 * The database being in `isolated` rather than `private-egress` is the point:
 * even a compromised database instance has no path out.
 */
export class NettleNetworkStack extends Stack {
  public readonly vpc: Vpc;
  public readonly connectorSecurityGroup: SecurityGroup;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    this.vpc = new Vpc(this, "Vpc", {
      maxAzs: 2,
      natGateways: 1,
      subnetConfiguration: [
        { name: "public", subnetType: SubnetType.PUBLIC, cidrMask: 24 },
        { name: "private-egress", subnetType: SubnetType.PRIVATE_WITH_EGRESS, cidrMask: 24 },
        { name: "isolated", subnetType: SubnetType.PRIVATE_ISOLATED, cidrMask: 24 },
      ],
    });

    // Secrets Manager over a private endpoint rather than out through NAT.
    // App Runner injects secrets using its own instance role outside this
    // VPC, so this is for anything the application itself looks up at
    // runtime; it keeps that traffic off the internet path entirely.
    this.vpc.addInterfaceEndpoint("SecretsManagerEndpoint", {
      service: InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      subnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
    });

    // Gateway endpoint (route-table based, no ENI, no NAT/hourly cost — free)
    // added to the ISOLATED subnets specifically, not private-egress: this is
    // what lets scan-worker-stack.ts's Fargate scan task (placed in isolated
    // subnets, same tier as the database, for the same "no route to the
    // internet at all" reason) reach S3 for its workspace/results handoff
    // without needing any internet route. The isolated subnets' route table
    // has no route to 0.0.0.0/0 (no IGW, no NAT) — this endpoint is the ONLY
    // non-local route added to it, so restricting egress security group
    // rules to "HTTPS, any destination" for anything placed in these subnets
    // can only ever actually reach S3 in practice, same reasoning already
    // applied to the database's own security group below.
    this.vpc.addGatewayEndpoint("IsolatedS3Endpoint", {
      service: GatewayVpcEndpointAwsService.S3,
      subnets: [{ subnetType: SubnetType.PRIVATE_ISOLATED }],
    });

    this.connectorSecurityGroup = new SecurityGroup(this, "ConnectorSecurityGroup", {
      vpc: this.vpc,
      description: "App Runner VPC connector for the Nettle API - egress only, no inbound rules",
      allowAllOutbound: false,
    });

    // Outbound HTTPS only. The connector needs to reach Stripe, the git hosts
    // and the database; none of that needs any other port, and restricting it
    // here limits what code running in a scan could attempt to reach.
    this.connectorSecurityGroup.addEgressRule(
      Peer.anyIpv4(),
      Port.tcp(443),
      "HTTPS to Stripe and the supported git hosts"
    );
    this.connectorSecurityGroup.addEgressRule(
      Peer.ipv4(this.vpc.vpcCidrBlock),
      Port.tcp(5432),
      "PostgreSQL to the database subnet"
    );

    new CfnOutput(this, "VpcId", { value: this.vpc.vpcId });
  }
}
