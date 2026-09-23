import { CfnOutput, Stack, type StackProps } from "aws-cdk-lib";
import { OpenIdConnectProvider, Role, WebIdentityPrincipal, PolicyStatement, Effect } from "aws-cdk-lib/aws-iam";
import type { Construct } from "constructs";

export interface NettleCiStackProps extends StackProps {
  /** e.g. "MariaD137/Nettle" */
  githubRepo: string;
  ecrRepositoryArn: string;
  /** frontend-stack.ts's bucket — grants exactly the `aws s3 sync` actions frontend-deploy.yml needs, nothing else. */
  frontendBucketArn: string;
  /** frontend-stack.ts's distribution — grants exactly cloudfront:CreateInvalidation, scoped to this one distribution. */
  frontendDistributionId: string;
}

/**
 * GitHub Actions authenticates via OIDC — no long-lived AWS access keys
 * stored in GitHub at any point. Scoped to exactly what this repo's deploy
 * workflows do: push images to this one ECR repo (backend-deploy.yml,
 * backend-deploy-staging.yml), and sync/invalidate this one frontend
 * bucket/distribution (frontend-deploy.yml). Nothing else in the account.
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

    // frontend-deploy.yml's `aws s3 sync` — read/write/delete objects (a
    // sync removes files no longer in the new build) plus ListBucket, which
    // sync needs to diff against what's already there. Scoped to this one
    // bucket, nothing account-wide.
    deployRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ["s3:PutObject", "s3:DeleteObject", "s3:GetObject"],
        resources: [`${props.frontendBucketArn}/*`],
      })
    );
    deployRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ["s3:ListBucket"],
        resources: [props.frontendBucketArn],
      })
    );

    // frontend-deploy.yml's post-sync CloudFront invalidation — without
    // this, an edge location keeps serving a stale cached response (index.html
    // in particular) for up to its TTL after every deploy. Scoped to this
    // one distribution via its own ARN, not "*".
    deployRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ["cloudfront:CreateInvalidation"],
        resources: [`arn:aws:cloudfront::${this.account}:distribution/${props.frontendDistributionId}`],
      })
    );

    new CfnOutput(this, "DeployRoleArn", { value: deployRole.roleArn });
  }
}
