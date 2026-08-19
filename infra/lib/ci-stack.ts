import { CfnOutput, Stack, type StackProps } from "aws-cdk-lib";
import { OpenIdConnectProvider, Role, WebIdentityPrincipal, PolicyStatement, Effect } from "aws-cdk-lib/aws-iam";
import type { Construct } from "constructs";

export interface NettleCiStackProps extends StackProps {
  /** e.g. "MariaD137/Nettle" */
  githubRepo: string;
  ecrRepositoryArn: string;
  /**
   * Frontend bucket/distribution ARNs, if frontend-stack.ts has actually
   * been deployed — optional so this stack can still deploy standalone
   * before the frontend stack exists. When present, the deploy role also
   * gets scoped permission to sync built frontend assets into the bucket
   * and invalidate the distribution's cache — see
   * .github/workflows/frontend-deploy.yml.
   */
  frontendBucketArn?: string;
  frontendDistributionArn?: string;
}

/**
 * GitHub Actions authenticates via OIDC — no long-lived AWS access keys
 * stored in GitHub at any point. Deliberately does NOT include permission
 * to run `cdk deploy` or otherwise create/modify infrastructure — that
 * stays a human-run action with the deployer's own credentials (see
 * AWS_GITHUB_DEPLOYMENT.md). This role only gets the narrow, repeatable
 * deploy-time actions CI actually performs against infrastructure that
 * already exists: push images to the one ECR repo, and (once the frontend
 * stack exists) sync built assets to the one frontend bucket and
 * invalidate the one CloudFront distribution.
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

    if (props.frontendBucketArn) {
      deployRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ["s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
          resources: [props.frontendBucketArn, `${props.frontendBucketArn}/*`],
        })
      );
    }

    if (props.frontendDistributionArn) {
      deployRole.addToPolicy(
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ["cloudfront:CreateInvalidation"],
          resources: [props.frontendDistributionArn],
        })
      );
    }

    new CfnOutput(this, "DeployRoleArn", { value: deployRole.roleArn });
  }
}
