#!/usr/bin/env node
import { App } from "aws-cdk-lib";
import { SubnetType } from "aws-cdk-lib/aws-ec2";
import { NettleNetworkStack } from "../lib/network-stack";
import { NettleDatabaseStack } from "../lib/database-stack";
import { NettleEcrStack } from "../lib/ecr-stack";
import { NettleScanWorkerStack } from "../lib/scan-worker-stack";
import { NettleApiStack } from "../lib/api-stack";
import { NettleFrontendStack } from "../lib/frontend-stack";
import { NettleWafCloudFrontStack, NettleWafApiStack } from "../lib/waf-stack";
import { NettleCiStack } from "../lib/ci-stack";

const app = new App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION || "us-east-1",
};

const network = new NettleNetworkStack(app, "Nettle-Network", { env });

// The database is its own stack so that tearing down or replacing the API
// cannot take the data with it: the stack that holds customer state has a
// different lifecycle from the stack that holds a container image.
const database = new NettleDatabaseStack(app, "Nettle-Database", {
  env,
  vpc: network.vpc,
  connectorSecurityGroup: network.connectorSecurityGroup,
  production: true,
});

// Its own stack, deployed and populated with a real image BEFORE Nettle-Api
// exists — see ecr-stack.ts for why this ordering is required, not optional.
const ecr = new NettleEcrStack(app, "Nettle-Ecr", { env });

// True scan sandboxing (see that file's own doc comment): an isolated ECS
// Fargate task the API dispatches untrusted scan execution to, instead of
// running it in the API's own process. Production only for this round —
// staging keeps the pre-existing in-process fallback (a Fargate task
// definition is pinned to one image tag at registration time, so giving
// staging its own isolated path would mean a second cluster/task
// definition tracking :staging; not done here, a disclosed, deliberate
// scope-narrowing rather than an oversight).
const scanWorker = new NettleScanWorkerStack(app, "Nettle-ScanWorker", {
  env,
  vpc: network.vpc,
  repository: ecr.repository,
});

const api = new NettleApiStack(app, "Nettle-Api", {
  env,
  vpc: network.vpc,
  connectorSecurityGroup: network.connectorSecurityGroup,
  databaseSecret: database.secret,
  databaseEndpoint: database.instance.dbInstanceEndpointAddress,
  repository: ecr.repository,
  // backend-deploy.yml deploys an immutable :<git-sha> image via an explicit
  // `aws apprunner update-service` call instead of a mutable :latest tag
  // App Runner watches on its own — see api-stack.ts's own prop comment.
  autoDeploymentsEnabled: false,
  scanWorker: {
    clusterArn: scanWorker.cluster.clusterArn,
    taskDefinitionArn: scanWorker.taskDefinition.taskDefinitionArn,
    subnetIds: network.vpc.selectSubnets({ subnetType: SubnetType.PRIVATE_ISOLATED }).subnetIds.join(","),
    securityGroupId: scanWorker.taskSecurityGroup.securityGroupId,
    workspaceBucketName: scanWorker.workspaceBucket.bucketName,
    taskRoleArn: scanWorker.taskRoleArn,
    executionRoleArn: scanWorker.executionRoleArn,
  },
});

/**
 * Staging: a second, independent environment tracking the ECR :staging tag
 * that backend-deploy-staging.yml (triggered on every push to `develop`)
 * has been pushing since before anything here consumed it — that workflow
 * ran successfully and had nowhere for its output to go. These two stacks
 * close that gap.
 *
 * Shares Nettle-Network (same VPC) with production — there's no requirement
 * for network-level separation between the two, only for the data and the
 * running service to be independent, which the stageName suffix on each of
 * these stacks' physical resource names (secrets, VPC connector, service
 * name) guarantees; see database-stack.ts's and api-stack.ts's own comments
 * on that prop. Does NOT share Nettle-Database, Nettle-Api, or either
 * stack's Secrets Manager secret with production — a staging deploy can
 * never read or write production customer data or production Stripe keys.
 *
 * `production: false` on the database (database-stack.ts) gets staging a
 * cheaper, destroyable instance — 1-day backup retention, no deletion
 * protection, RemovalPolicy.DESTROY — appropriate for an environment that's
 * meant to be disposable, unlike Nettle-Database.
 */
const stagingDatabase = new NettleDatabaseStack(app, "Nettle-Database-Staging", {
  env,
  vpc: network.vpc,
  connectorSecurityGroup: network.connectorSecurityGroup,
  production: false,
  stageName: "staging",
});

new NettleApiStack(app, "Nettle-Api-Staging", {
  env,
  vpc: network.vpc,
  connectorSecurityGroup: network.connectorSecurityGroup,
  databaseSecret: stagingDatabase.secret,
  databaseEndpoint: stagingDatabase.instance.dbInstanceEndpointAddress,
  repository: ecr.repository, // same ECR repo as production — only the image TAG differs
  stageName: "staging",
  imageTag: "staging",
});

// AWS WAF: an additional edge-layer protection in front of both public
// entry points (see waf-stack.ts's own doc comment for the full design and
// why blindly enabling every managed rule would be wrong for this specific
// API's own traffic). NettleWafCloudFrontStack is hardcoded to us-east-1 —
// an AWS WAF requirement for the CLOUDFRONT scope, independent of whatever
// region the rest of this app deploys to — with crossRegionReferences
// enabled on both ends so Nettle-Frontend (below) can consume its ACL ARN
// even if they end up in different regions.
const wafCloudFront = new NettleWafCloudFrontStack(app, "Nettle-Waf-CloudFront", {
  env: { account: env.account, region: "us-east-1" },
  crossRegionReferences: true,
});

new NettleWafApiStack(app, "Nettle-Waf-Api", {
  env,
  apiServiceArn: api.serviceArn,
});

// Custom domain (see frontend-stack.ts's own props for the full reasoning):
// both env vars are optional and read together — the deployer's own real
// domain and an already-validated ACM certificate ARN, never invented or
// auto-created here. Neither set (the default): the distribution keeps
// serving only its own *.cloudfront.net domain, unchanged.
const frontendDomain = process.env.FRONTEND_DOMAIN;
const frontendCertificateArn = process.env.FRONTEND_CERTIFICATE_ARN;

// S3 + CloudFront hosting for frontend/'s Vite build. Depends on Nettle-Api
// only for its serviceUrl (allowed through the CSP's connect-src — see
// frontend-stack.ts) — no other coupling, and its own deploy/teardown is
// otherwise fully independent of the API.
const frontend = new NettleFrontendStack(app, "Nettle-Frontend", {
  env,
  crossRegionReferences: true,
  apiOrigin: `https://${api.serviceUrl}`,
  webAclArn: wafCloudFront.webAclArn,
  domainName: frontendDomain,
  certificateArn: frontendCertificateArn,
});

new NettleCiStack(app, "Nettle-CI", {
  env,
  githubRepo: "MariaD137/Nettle",
  // Depends on the ECR stack directly, not on Nettle-Api — CI needs push
  // access to the repo regardless of whether the App Runner service stack
  // has been deployed yet, and this keeps that permission from being
  // entangled with the service's own deploy order.
  ecrRepositoryArn: ecr.repository.repositoryArn,
  frontendBucketArn: frontend.bucket.bucketArn,
  frontendDistributionId: frontend.distribution.distributionId,
});
