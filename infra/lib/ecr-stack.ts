import { CfnOutput, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import { Repository, TagMutability } from "aws-cdk-lib/aws-ecr";
import type { Construct } from "constructs";

/**
 * The ECR repository, on its own — deliberately not part of Nettle-Api.
 *
 * AWS::AppRunner::Service (created in api-stack.ts) references this repo's
 * `:latest` tag at creation time and CloudFormation waits for the service to
 * reach RUNNING before considering that resource complete. On a first-ever
 * deploy there is no image yet, so if the repo and the service were created
 * in the same stack, the service would fail to pull, CREATE_FAILED, and
 * CloudFormation would roll back the *entire* stack — deleting the repo it
 * had just created moments earlier along with everything else.
 *
 * Keeping the repo in its own stack breaks that chicken-and-egg: deploy this
 * stack, push a real image into the now-stable repo, and only then deploy
 * Nettle-Api, which creates the App Runner service against an image that
 * already exists.
 */
export class NettleEcrStack extends Stack {
  public readonly repository: Repository;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    this.repository = new Repository(this, "ScanApiRepo", {
      repositoryName: "nettle-api",
      imageTagMutability: TagMutability.MUTABLE, // App Runner auto-deploys by watching :latest
      removalPolicy: RemovalPolicy.DESTROY,
      emptyOnDelete: true,
    });

    new CfnOutput(this, "RepositoryUri", { value: this.repository.repositoryUri });
  }
}
