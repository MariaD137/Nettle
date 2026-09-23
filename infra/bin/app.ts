#!/usr/bin/env node
import { App } from "aws-cdk-lib";
import { NettleNetworkStack } from "../lib/network-stack";
import { NettleDatabaseStack } from "../lib/database-stack";
import { NettleEcrStack } from "../lib/ecr-stack";
import { NettleApiStack } from "../lib/api-stack";
import { NettleFrontendStack } from "../lib/frontend-stack";
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

const api = new NettleApiStack(app, "Nettle-Api", {
  env,
  vpc: network.vpc,
  connectorSecurityGroup: network.connectorSecurityGroup,
  databaseSecret: database.secret,
  databaseEndpoint: database.instance.dbInstanceEndpointAddress,
  repository: ecr.repository,
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

// S3 + CloudFront hosting for frontend/'s Vite build. Depends on Nettle-Api
// only for its serviceUrl (allowed through the CSP's connect-src — see
// frontend-stack.ts) — no other coupling, and its own deploy/teardown is
// otherwise fully independent of the API.
const frontend = new NettleFrontendStack(app, "Nettle-Frontend", {
  env,
  apiOrigin: `https://${api.serviceUrl}`,
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
