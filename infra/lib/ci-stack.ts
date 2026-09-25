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
  /**
   * ARN of an already-existing `token.actions.githubusercontent.com` OIDC
   * provider in this account, if one exists. AWS allows only one OIDC
   * provider per URL per account — a second CREATE against the same URL
   * fails with EntityAlreadyExistsException, which is exactly what this repo
   * hit deploying Nettle-CI against an account that already had this
   * provider (from an earlier attempt, or something else in the account
   * unrelated to Nettle). Left undefined (the default), this stack creates
   * a new provider exactly as it always has — set this only when a deploy
   * has actually failed with that error, using the ARN
   * `aws iam list-open-id-connect-providers` prints for the existing one.
   */
  githubOidcProviderArn?: string;
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

    const provider = props.githubOidcProviderArn
      ? OpenIdConnectProvider.fromOpenIdConnectProviderArn(this, "GithubOidcProvider", props.githubOidcProviderArn)
      : new OpenIdConnectProvider(this, "GithubOidcProvider", {
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

    // backend-deploy.yml's production deploy: after pushing an immutable
    // :<git-sha> image, it looks up Nettle-Api's App Runner service by name
    // (ListServices — this action has no resource-level scoping, so it's
    // granted account-wide; it only returns service names/ARNs, nothing
    // sensitive) and updates that one service's image (DescribeService to
    // read its current source configuration without clobbering the
    // ECR access role / port / env vars, then UpdateService with only the
    // image identifier changed). Scoped to service names starting
    // "nettle-api" — exactly api-stack.ts's `nettle-api${suffix}` naming
    // (production "nettle-api", staging "nettle-api-staging") — never "*".
    // backend-deploy-staging.yml does not use this: staging keeps watching
    // its :staging tag via App Runner's own autoDeploymentsEnabled (see
    // api-stack.ts's autoDeploymentsEnabled prop), unchanged from before.
    deployRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ["apprunner:ListServices"],
        resources: ["*"], // ListServices does not support resource-level scoping
      })
    );
    deployRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ["apprunner:DescribeService", "apprunner:UpdateService"],
        resources: [`arn:aws:apprunner:${this.region}:${this.account}:service/nettle-api*`],
      })
    );

    new CfnOutput(this, "DeployRoleArn", { value: deployRole.roleArn });
  }
}
