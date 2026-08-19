import { CfnOutput, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import { SecurityGroup, Peer, Port, SubnetType, InstanceType, InstanceClass, InstanceSize } from "aws-cdk-lib/aws-ec2";
import { DatabaseInstance, DatabaseInstanceEngine, PostgresEngineVersion, Credentials } from "aws-cdk-lib/aws-rds";
import type { Vpc, SecurityGroup as SecurityGroupType } from "aws-cdk-lib/aws-ec2";
import type { Construct } from "constructs";

export interface NettleDatabaseStackProps extends StackProps {
  vpc: Vpc;
  /** The App Runner VPC connector's security group — the only thing allowed to reach RDS. */
  apiSecurityGroup: SecurityGroupType;
}

/**
 * Prepared, not deployed: this stack has never been applied to a real AWS
 * account (no AWS account exists to apply it to). It is real, synthesizable
 * CDK — `cdk synth` produces a valid CloudFormation template — but "PASS"
 * here means "the code is correct," not "an RDS instance exists."
 *
 * The application side of this is no longer deferred: the backend's
 * data-access layer (backend/src/db/index.ts) is PostgreSQL-only now, with
 * no SQLite fallback (see backend/src/db/postgres/README.md) — it requires
 * a real PostgreSQL connection to start at all. What's still pending is
 * purely the AWS side: an actual `cdk deploy Nettle-Database` against a
 * real account, and then wiring this stack's outputs into Nettle-Api (see
 * api-stack.ts's `databaseSecretArn`/`databaseEndpointAddress` props and
 * bin/app.ts's REQUIRES AWS CONFIGURATION note) — neither of which this
 * repository can do on its own.
 */
export class NettleDatabaseStack extends Stack {
  public readonly instanceEndpoint: string;
  public readonly secretArn: string;

  constructor(scope: Construct, id: string, props: NettleDatabaseStackProps) {
    super(scope, id, props);

    const dbSecurityGroup = new SecurityGroup(this, "DatabaseSecurityGroup", {
      vpc: props.vpc,
      description: "Nettle RDS PostgreSQL - inbound only from the App Runner VPC connector",
      allowAllOutbound: false,
    });
    dbSecurityGroup.addIngressRule(
      Peer.securityGroupId(props.apiSecurityGroup.securityGroupId),
      Port.tcp(5432),
      "Allow the API's VPC connector to reach Postgres"
    );

    // CDK generates the actual password at deploy time and stores it in a
    // new Secrets Manager secret — nobody, including whoever runs `cdk
    // deploy`, ever types or sees a plaintext password in the process.
    // This is the standard, safe CDK pattern for exactly this reason.
    const instance = new DatabaseInstance(this, "Database", {
      engine: DatabaseInstanceEngine.postgres({ version: PostgresEngineVersion.VER_16 }),
      // Smallest available burstable instance — right-sized for "just
      // migrated off SQLite," not for real production load. Resize once
      // there's real traffic to size against.
      instanceType: InstanceType.of(InstanceClass.T4G, InstanceSize.MICRO),
      vpc: props.vpc,
      vpcSubnets: { subnetType: SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [dbSecurityGroup],
      credentials: Credentials.fromGeneratedSecret("nettle_admin"),
      databaseName: "nettle",
      allocatedStorage: 20,
      storageEncrypted: true,
      multiAz: false, // single-AZ for cost; revisit once this is carrying real customer data
      deletionProtection: false, // this stack is unproven — flip to true before any real deployment carries real data
      removalPolicy: RemovalPolicy.SNAPSHOT,
      backupRetention: undefined, // RDS default (7 days) is fine to start
      publiclyAccessible: false,
    });

    this.instanceEndpoint = instance.dbInstanceEndpointAddress;
    this.secretArn = instance.secret!.secretArn;

    new CfnOutput(this, "DatabaseEndpoint", {
      value: instance.dbInstanceEndpointAddress,
      description: "Pass this as api-stack.ts's databaseEndpointAddress prop (see bin/app.ts)",
    });
    new CfnOutput(this, "DatabaseSecretArn", {
      value: instance.secret!.secretArn,
      // Credentials.fromGeneratedSecret("nettle_admin") above puts only
      // `username` and the generated `password` in this secret — no
      // host/port/dbname (this stack configures no SecretTargetAttachment
      // rotation, which is what would add those). Pass this as
      // api-stack.ts's databaseSecretArn prop (see bin/app.ts); host/port/
      // dbname come from DatabaseEndpoint above and a fixed default
      // instead, not from this secret.
      description: "Secrets Manager secret holding username/password only — never a plaintext DATABASE_URL",
    });
  }
}
