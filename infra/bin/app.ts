#!/usr/bin/env node
import { App } from "aws-cdk-lib";
import { NettleNetworkStack } from "../lib/network-stack";
import { NettleApiStack } from "../lib/api-stack";
import { NettleDatabaseStack } from "../lib/database-stack";
import { NettleFrontendStack } from "../lib/frontend-stack";
import { NettleCiStack } from "../lib/ci-stack";

const app = new App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION || "us-east-1",
};

const network = new NettleNetworkStack(app, "Nettle-Network", { env });

const api = new NettleApiStack(app, "Nettle-Api", {
  env,
  vpc: network.vpc,
  connectorSecurityGroup: network.connectorSecurityGroup,
  // REQUIRES AWS CONFIGURATION: the backend has no SQLite fallback and
  // will not start without a real PostgreSQL connection (see
  // backend/src/db/postgres/README.md). These two values only exist after
  // a human has deployed Nettle-Database in a real AWS account — this
  // repository does not do that on its own, and these are deliberately
  // left unset here rather than guessed. Once Nettle-Database has been
  // deployed once, fill these in from its outputs (`cdk deploy
  // Nettle-Database` prints `DatabaseSecretArn` and `DatabaseEndpoint`)
  // and redeploy Nettle-Api:
  //   databaseSecretArn: "arn:aws:secretsmanager:...",
  //   databaseEndpointAddress: "....rds.amazonaws.com",
  // Deliberately not wired automatically by referencing the
  // NettleDatabaseStack instance below — that would create a hard
  // CloudFormation cross-stack dependency, so Nettle-Api could no longer
  // be deployed or updated independently of Nettle-Database. Whether to
  // couple them that tightly is an operator decision for whoever actually
  // deploys this, not something to decide by default here.
});

// Not deployed as part of the default flow: provisioning a real RDS
// instance is a deliberate step (see database-stack.ts and
// AWS_GITHUB_DEPLOYMENT.md), not something that should happen as a side
// effect of deploying the API. Kept in the app tree so `cdk synth
// Nettle-Database` / `cdk deploy Nettle-Database` work when that step is
// actually taken.
new NettleDatabaseStack(app, "Nettle-Database", {
  env,
  vpc: network.vpc,
  apiSecurityGroup: network.connectorSecurityGroup,
});

const frontend = new NettleFrontendStack(app, "Nettle-Frontend", { env });

new NettleCiStack(app, "Nettle-CI", {
  env,
  githubRepo: "MariaD137/Nettle",
  ecrRepositoryArn: api.repositoryArn,
  frontendBucketArn: `arn:aws:s3:::${frontend.bucketName}`,
  // CloudFront ARNs are always in the global "us-east-1" partition
  // namespace but scoped to the account, not the region — formatArn's own
  // `region: ""` handles that; using the raw env.account string here
  // instead would literally serialize the word "undefined" into the
  // template in environment-agnostic (no CDK_DEFAULT_ACCOUNT) synthesis.
  frontendDistributionArn: frontend.formatArn({
    service: "cloudfront",
    region: "",
    resource: "distribution",
    resourceName: frontend.distributionId,
  }),
});
