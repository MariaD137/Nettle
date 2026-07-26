import { CfnOutput, Stack, type StackProps } from "aws-cdk-lib";
import { OpenIdConnectProvider, Role, WebIdentityPrincipal, PolicyStatement, Effect } from "aws-cdk-lib/aws-iam";
import type { Construct } from "constructs";

export interface NettleCiStackProps extends StackProps {
  /** e.g. "MariaD137/Nettle" */
  githubRepo: string;
  ecrRepositoryArn: string;
}

/**
 * GitHub Actions authenticates via OIDC — no long-lived AWS access keys
 * stored in GitHub at any point. Scoped to exactly one thing: push images
 * to this one ECR repo. It cannot touch anything else in the account.
 */
export class NettleCiStack extends Stack {
  constructor(scope: Construct, id: string, props: NettleCiStackProps) {
    super(scope, id, props);

    const provider = new OpenIdConnectProvider(this, "GithubOidcProvider", {
      url: "https://token.actions.githubusercontent.com",
      clientIds: ["sts.amazonaws.com"],
    });

    const deployRole = new Role(this, "GithubActionsDeployRole", {
      roleName: "nettle-github-actions-deploy",
      assumedBy: new WebIdentityPrincipal(provider.openIdConnectProviderArn, {
        StringEquals: {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        },
        StringLike: {
          "token.actions.githubusercontent.com:sub": `repo:${props.githubRepo}:*`,
        },
      }),
      description: "Assumed by GitHub Actions to push images to the Nettle API's ECR repo",
    });

    deployRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ["ecr:GetAuthorizationToken"],
        resources: ["*"], // this action does not support resource-level scoping
      })
    );

    deployRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:BatchGetImage",
        ],
        resources: [props.ecrRepositoryArn],
      })
    );

    new CfnOutput(this, "DeployRoleArn", { value: deployRole.roleArn });
  }
}
