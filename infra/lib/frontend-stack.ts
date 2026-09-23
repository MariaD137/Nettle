import { CfnOutput, Duration, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import { Bucket, BlockPublicAccess, BucketEncryption } from "aws-cdk-lib/aws-s3";
import {
  Distribution,
  ViewerProtocolPolicy,
  CachePolicy,
  ResponseHeadersPolicy,
  HeadersFrameOption,
  HeadersReferrerPolicy,
  PriceClass,
} from "aws-cdk-lib/aws-cloudfront";
import { S3BucketOrigin } from "aws-cdk-lib/aws-cloudfront-origins";
import type { Construct } from "constructs";

export interface NettleFrontendStackProps extends StackProps {
  /**
   * The API's public origin, scheme included (e.g.
   * `https://${api.serviceUrl}` from api-stack.ts) — allowed through the
   * response headers policy's Content-Security-Policy `connect-src` so the
   * SPA can actually call it. Required, not optional: a CSP with no
   * `connect-src` entry for the API would silently block every fetch() this
   * app makes once real security headers are enforced.
   */
  apiOrigin: string;
}

/**
 * Static hosting for `frontend/`'s Vite build output — a private S3 bucket
 * behind CloudFront, never a public bucket or S3 static-website endpoint.
 *
 * Deliberately infrastructure-only, the same separation api-stack.ts/
 * ecr-stack.ts already use for the backend: this stack creates the bucket
 * and distribution; it does NOT bundle `frontend/dist` as a CDK asset
 * (no BucketDeployment construct). A GitHub Actions workflow
 * (.github/workflows/frontend-deploy.yml) builds the Vite app and syncs
 * the output into the bucket, then invalidates the distribution — the
 * exact same "build out-of-band, CDK only owns the running
 * infrastructure" shape backend-deploy.yml already uses for the API
 * (push an image; App Runner's autoDeploymentsEnabled picks it up). Baking
 * the frontend into a CDK asset instead would mean every frontend-only
 * change requires a CDK deploy (a different, heavier pipeline with
 * different required permissions) just to ship a CSS tweak.
 */
export class NettleFrontendStack extends Stack {
  public readonly bucket: Bucket;
  public readonly distribution: Distribution;
  public readonly distributionDomainName: string;

  constructor(scope: Construct, id: string, props: NettleFrontendStackProps) {
    super(scope, id, props);

    // No explicit bucketName: S3 bucket names are unique GLOBALLY (across
    // every AWS account, not just this one), unlike every other physical
    // name elsewhere in this app (ECR repo, Secrets Manager secret, App
    // Runner service — all only account+region-unique). Letting CDK
    // generate one avoids a real deploy-time collision risk a fixed name
    // like "nettle-frontend" would have against every other AWS customer
    // who picked the same obvious name.
    this.bucket = new Bucket(this, "FrontendBucket", {
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      encryption: BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      // Static build output — always reproducible by re-running the build,
      // never customer data. Safe to destroy along with the stack, unlike
      // Nettle-Database's deliberately-retained instance.
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // Security headers applied to every response, regardless of the S3
    // object's own metadata — this is what makes them real rather than
    // dependent on the deploy workflow remembering to set them correctly on
    // every sync. No `unsafe-inline`/`unsafe-eval` anywhere: the Vite build
    // emits no inline <script>/<style> at all (checked directly against
    // frontend/dist/index.html — every asset is an external, hashed,
    // same-origin file), so a strict CSP doesn't break the app.
    const securityHeaders = new ResponseHeadersPolicy(this, "SecurityHeaders", {
      comment: "Nettle frontend — strict CSP, no inline script/style, HTTPS-only",
      securityHeadersBehavior: {
        contentSecurityPolicy: {
          override: true,
          contentSecurityPolicy: [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data:",
            "font-src 'self'",
            `connect-src 'self' ${props.apiOrigin}`,
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
          ].join("; "),
        },
        contentTypeOptions: { override: true }, // X-Content-Type-Options: nosniff
        frameOptions: { frameOption: HeadersFrameOption.DENY, override: true },
        referrerPolicy: { referrerPolicy: HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN, override: true },
        strictTransportSecurity: {
          accessControlMaxAge: Duration.days(730),
          includeSubdomains: true,
          preload: true,
          override: true,
        },
      },
    });

    this.distribution = new Distribution(this, "FrontendDistribution", {
      comment: "Nettle frontend (SPA)",
      defaultRootObject: "index.html",
      // US/Europe edge locations only — the cheaper price class. Nettle has
      // no announced traffic outside those regions yet; widen this
      // (PriceClass.PRICE_CLASS_ALL) once real usage justifies the cost.
      priceClass: PriceClass.PRICE_CLASS_100,
      defaultBehavior: {
        origin: S3BucketOrigin.withOriginAccessControl(this.bucket),
        viewerProtocolPolicy: ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: securityHeaders,
      },
      // Client-side routing (react-router): a request for /projects/abc has
      // no matching S3 object, so the private bucket returns 403 (not 404 —
      // that's how a private, OAC-fronted bucket answers a missing key).
      // Both map to index.html with an explicit 200, not a redirect, so the
      // browser's URL bar keeps the route the user actually navigated to
      // and react-router itself resolves it client-side. ttl: 0 so a
      // genuinely-missing asset doesn't get this fallback cached over a
      // real fix.
      errorResponses: [
        { httpStatus: 403, responseHttpStatus: 200, responsePagePath: "/index.html", ttl: Duration.seconds(0) },
        { httpStatus: 404, responseHttpStatus: 200, responsePagePath: "/index.html", ttl: Duration.seconds(0) },
      ],
    });

    this.distributionDomainName = this.distribution.distributionDomainName;

    new CfnOutput(this, "BucketName", { value: this.bucket.bucketName });
    new CfnOutput(this, "DistributionId", { value: this.distribution.distributionId });
    new CfnOutput(this, "DistributionDomainName", {
      value: this.distributionDomainName,
      description: "Set as VITE_API's counterpart on the frontend build — the URL customers actually visit, or the CNAME target for a custom domain",
    });
  }
}
