#!/usr/bin/env node
import { App } from "aws-cdk-lib";
import { NettleNetworkStack } from "../lib/network-stack";
import { NettleApiStack } from "../lib/api-stack";
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
});

new NettleCiStack(app, "Nettle-CI", {
  env,
  githubRepo: "MariaD137/Nettle",
  ecrRepositoryArn: api.repositoryArn,
});
