import { CfnOutput, RemovalPolicy, Stack, type StackProps, Duration } from "aws-cdk-lib";
import { Bucket, BlockPublicAccess, BucketAccessControl } from "aws-cdk-lib/aws-s3";
import { Distribution, ViewerProtocolPolicy, AllowedMethods, CachePolicy } from "aws-cdk-lib/aws-cloudfront";
import { S3BucketOrigin } from "aws-cdk-lib/aws-cloudfront-origins";
import type { Construct } from "constructs";

/**
 * Prepared, not deployed — same caveat as database-stack.ts: this has
 * never been applied to a real AWS account. `cdk synth` verifies the
 * template is valid; it does not verify a distribution exists or serves
 * traffic. No GitHub Actions workflow currently deploys built frontend
 * assets into this bucket (a real gap — see AWS_GITHUB_DEPLOYMENT.md).
 *
 * The bucket has no public access at all; CloudFront reaches it through an
 * Origin Access Identity, which is the only principal with read access.
 */
export class NettleFrontendStack extends Stack {
  public readonly bucketName: string;
  public readonly distributionId: string;
  public readonly distributionDomainName: string;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const bucket = new Bucket(this, "FrontendBucket", {
      bucketName: undefined, // let CloudFormation generate a globally-unique name
      accessControl: BucketAccessControl.PRIVATE,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      encryption: undefined, // S3-managed (SSE-S3) default is fine for static, non-secret build output
      removalPolicy: RemovalPolicy.RETAIN, // never auto-delete a live frontend's bucket on stack teardown
      versioned: false,
    });

    const distribution = new Distribution(this, "FrontendDistribution", {
      defaultBehavior: {
        // Origin Access Control (OAC), the current recommended approach —
        // it wires the bucket policy automatically so only this
        // distribution can read the bucket, no separate identity/grant
        // needed the way the older Origin Access Identity required.
        origin: S3BucketOrigin.withOriginAccessControl(bucket),
        viewerProtocolPolicy: ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: AllowedMethods.ALLOW_GET_HEAD,
        cachePolicy: CachePolicy.CACHING_OPTIMIZED,
      },
      defaultRootObject: "index.html",
      // A client-side-routed SPA (react-router) needs every unknown path to
      // still resolve to index.html — the app's own router decides what to
      // render, not S3/CloudFront. Without this, refreshing on e.g.
      // /projects/abc directly would 403/404 instead of loading the app.
      errorResponses: [
        { httpStatus: 403, responseHttpStatus: 200, responsePagePath: "/index.html", ttl: Duration.seconds(0) },
        { httpStatus: 404, responseHttpStatus: 200, responsePagePath: "/index.html", ttl: Duration.seconds(0) },
      ],
    });

    this.bucketName = bucket.bucketName;
    this.distributionId = distribution.distributionId;
    this.distributionDomainName = distribution.distributionDomainName;

    new CfnOutput(this, "FrontendBucketName", { value: bucket.bucketName });
    new CfnOutput(this, "FrontendDistributionId", { value: distribution.distributionId });
    new CfnOutput(this, "FrontendUrl", { value: `https://${distribution.distributionDomainName}` });
  }
}
