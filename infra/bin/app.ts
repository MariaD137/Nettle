#!/usr/bin/env node
import { App } from "aws-cdk-lib";
import { NettleNetworkStack } from "../lib/network-stack";
import { NettleDatabaseStack } from "../lib/database-stack";
import { NettleEcrStack } from "../lib/ecr-stack";
import { NettleApiStack } from "../lib/api-stack";
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

new NettleCiStack(app, "Nettle-CI", {
  env,
  githubRepo: "MariaD137/Nettle",
  // Depends on the ECR stack directly, not on Nettle-Api — CI needs push
  // access to the repo regardless of whether the App Runner service stack
  // has been deployed yet, and this keeps that permission from being
  // entangled with the service's own deploy order.
  ecrRepositoryArn: ecr.repository.repositoryArn,
});
