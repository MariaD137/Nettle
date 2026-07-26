import { Stack, type StackProps } from "aws-cdk-lib";
import { Vpc, SubnetType, SecurityGroup, Peer, Port } from "aws-cdk-lib/aws-ec2";
import type { Construct } from "constructs";

/**
 * Deliberately minimal: isolated subnets only, zero NAT gateways, no internet
 * gateway at all. Tier 1 has no persistent data store and makes no outbound
 * calls today, and it executes code from strangers — the network itself
 * should make "call home" impossible by construction, not by convention.
 *
 * Nothing here is inbound-reachable from the internet directly; App Runner's
 * public endpoint lives outside this VPC and reaches the service through the
 * VPC connector's ENIs, not through a gateway.
 */
export class NettleNetworkStack extends Stack {
  public readonly vpc: Vpc;
  public readonly connectorSecurityGroup: SecurityGroup;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    this.vpc = new Vpc(this, "Vpc", {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        {
          name: "isolated",
          subnetType: SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24,
        },
      ],
    });

    this.connectorSecurityGroup = new SecurityGroup(this, "ConnectorSecurityGroup", {
      vpc: this.vpc,
      description: "App Runner VPC connector for the Nettle API - egress only, no inbound rules",
      allowAllOutbound: false,
    });

    // Outbound is scoped to the VPC's own CIDR only. With no NAT/IGW attached
    // to this VPC in the first place, there is nowhere for wider egress to
    // go regardless — this rule just makes the intent explicit at the SG level too.
    this.connectorSecurityGroup.addEgressRule(
      Peer.ipv4(this.vpc.vpcCidrBlock),
      Port.allTraffic(),
      "Allow traffic within the VPC only"
    );
  }
}
