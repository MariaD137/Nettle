import { Stack, type StackProps } from "aws-cdk-lib";
import { Vpc, SubnetType, SecurityGroup } from "aws-cdk-lib/aws-ec2";
import type { Construct } from "constructs";

/**
 * Originally zero-egress by design (Tier 1 made no outbound calls and
 * executed code from strangers, so the network made "call home"
 * impossible by construction). That assumption no longer holds: this app
 * now makes real outbound calls itself — Stripe checkout/portal session
 * creation, SMTP email, Twilio SMS, outbound webhook delivery to
 * customer-configured URLs, git clones for repo-based scans, and
 * SSRF-guarded fetches to scan targets for URL-based scans. A single NAT
 * gateway (not a redundant per-AZ pair — this isn't multi-AZ-critical
 * infrastructure, and the extra NAT gateways are pure cost) gives the
 * private subnets real internet egress while keeping them unreachable
 * from the internet inbound.
 *
 * Nothing here is inbound-reachable from the internet directly; App Runner's
 * public endpoint lives outside this VPC and reaches the service through the
 * VPC connector's ENIs, not through a gateway. RDS (see database-stack.ts)
 * lives in the same private subnets, reachable from the connector security
 * group only.
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
        {
          name: "public",
          subnetType: SubnetType.PUBLIC,
          cidrMask: 24,
        },
        {
          name: "private-egress",
          subnetType: SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 24,
        },
      ],
    });

    // Outbound calls this app actually makes go to arbitrary third-party
    // hosts (Stripe, whichever SMTP/Twilio endpoint is configured, any
    // customer's outbound webhook URL, any git host, any scan target URL)
    // — there is no fixed destination list to scope this to, hence
    // allowAllOutbound rather than a narrower rule set. Inbound stays
    // completely closed (no ingress rules at all); only egress is opened,
    // and only as far as the NAT gateway actually allows.
    this.connectorSecurityGroup = new SecurityGroup(this, "ConnectorSecurityGroup", {
      vpc: this.vpc,
      description: "App Runner VPC connector for the Nettle API - outbound internet + VPC, no inbound rules",
      allowAllOutbound: true,
    });
  }
}
