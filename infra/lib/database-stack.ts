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
 * Also not yet consumed by the application: the backend's data-access layer
 * (src/db/index.ts) still reads/writes SQLite exclusively — see
 * backend/src/db/postgres/README.md for why that conversion is deferred.
 * This stack exists so provisioning a real Postgres instance is ready the
 * moment that conversion happens, not before.
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

    new CfnOutput(this, "DatabaseEndpoint", { value: instance.dbInstanceEndpointAddress });
    new CfnOutput(this, "DatabaseSecretArn", {
      value: instance.secret!.secretArn,
      description: "Secrets Manager secret holding host/port/username/password/dbname — never a plaintext DATABASE_URL",
    });
  }
}
