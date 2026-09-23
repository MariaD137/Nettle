import { CfnOutput, Stack, type StackProps } from "aws-cdk-lib";
import { CfnWebACL, CfnWebACLAssociation } from "aws-cdk-lib/aws-wafv2";
import type { Construct } from "constructs";

/**
 * AWS WAF is an additional edge-layer protection — it never replaces the
 * application's own authorization checks, input validation, or
 * rate-limiting middleware (see middleware/rateLimit.ts, every route's own
 * requireAuth/requireProjectPlan gates, safeExtraction.ts's archive
 * validation). Those stay the actual security boundary; this is what
 * stops obviously-malicious traffic from ever reaching them at all.
 *
 * Two separate Web ACLs, in two separate stacks, because AWS WAF has two
 * different resource scopes that can't share a Web ACL:
 *   - CLOUDFRONT scope, which MUST be created in us-east-1 regardless of
 *     which region the rest of this app deploys to (an AWS WAF requirement
 *     for CloudFront specifically — CloudFront is a global service, and its
 *     WAF configuration lives in a single global store addressed via
 *     us-east-1). NettleWafCloudFrontStack's `env.region` is hardcoded to
 *     "us-east-1" for exactly this reason, independent of bin/app.ts's
 *     shared `env` (which is us-east-1 by default today, but isn't
 *     guaranteed to stay that way).
 *   - REGIONAL scope, for App Runner (and ALB/API Gateway/AppSync/Cognito/
 *     Verified Access) — created in the same region as the resource it
 *     protects. NettleWafApiStack uses whatever region Nettle-Api itself
 *     deploys to.
 */

const COMMON_RULE_GROUPS = [
  { name: "AWSManagedRulesCommonRuleSet", priority: 1 },
  { name: "AWSManagedRulesKnownBadInputsRuleSet", priority: 2 },
];

function managedRuleGroupRule(name: string, priority: number, vendorName = "AWS"): CfnWebACL.RuleProperty {
  return {
    name,
    priority,
    overrideAction: { none: {} },
    statement: { managedRuleGroupStatement: { vendorName, name } },
    visibilityConfig: {
      sampledRequestsEnabled: true,
      cloudWatchMetricsEnabled: true,
      metricName: name,
    },
  };
}

/**
 * A managed rule group that's evaluated and logged, but never blocks —
 * COUNT, not BLOCK. Used for the two rule groups whose false-positive risk
 * against Nettle's own actual traffic is real, not theoretical: request
 * bodies here legitimately contain findings/remediation TEXT full of the
 * exact patterns these rule groups exist to catch elsewhere (`eval(`,
 * `exec(`, SQL string concatenation, script tags) — a customer's own scan
 * report is nothing but examples of insecure code, by design. Blocking on
 * SQLi/XSS *pattern-matching* here would risk rejecting legitimate
 * findings-status updates (PATCH /api/projects/:id/findings/:hash, whose
 * body is free-text `notes`) rather than protecting anything the
 * application's own parameterized queries and React's own output-encoding
 * don't already handle. Left in COUNT mode rather than omitted entirely so
 * the signal is still visible (CloudWatch metrics/sampled requests) —
 * revisit once there's real traffic data to tell false positives from
 * actual attacks.
 */
function countOnlyManagedRuleGroupRule(name: string, priority: number, vendorName = "AWS"): CfnWebACL.RuleProperty {
  return {
    name,
    priority,
    overrideAction: { count: {} },
    statement: { managedRuleGroupStatement: { vendorName, name } },
    visibilityConfig: {
      sampledRequestsEnabled: true,
      cloudWatchMetricsEnabled: true,
      metricName: name,
    },
  };
}

/**
 * Blocks an individual IP once it crosses `limit` requests in a rolling
 * 5-minute window (AWS WAF's fixed rate-based-rule evaluation window — not
 * configurable to a shorter period at this rule type). This is a broad
 * flood/DoS backstop at the edge, deliberately coarse and set well above
 * any legitimate single-visitor traffic pattern — it is NOT a replacement
 * for the application's own per-route, per-account rate limiters
 * (middleware/rateLimit.ts), which stay the precise, account-aware control;
 * this just stops a flood from reaching the application at all.
 */
function rateLimitRule(priority: number, limit: number): CfnWebACL.RuleProperty {
  return {
    name: "RateLimitPerIp",
    priority,
    action: { block: {} },
    statement: { rateBasedStatement: { limit, aggregateKeyType: "IP" } },
    visibilityConfig: {
      sampledRequestsEnabled: true,
      cloudWatchMetricsEnabled: true,
      metricName: "RateLimitPerIp",
    },
  };
}

/**
 * WAF for Nettle-Frontend's CloudFront distribution — pure static asset
 * serving (see frontend-stack.ts), no file uploads, no legitimate
 * code-shaped request bodies at all, so the full managed rule set is safe
 * to run in BLOCK mode here without the false-positive risk the API's own
 * ACL has to work around.
 */
export class NettleWafCloudFrontStack extends Stack {
  public readonly webAclArn: string;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const acl = new CfnWebACL(this, "FrontendWebAcl", {
      name: "nettle-frontend-waf",
      scope: "CLOUDFRONT",
      defaultAction: { allow: {} },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: "nettle-frontend-waf",
      },
      rules: [
        ...COMMON_RULE_GROUPS.map((g) => managedRuleGroupRule(g.name, g.priority)),
        managedRuleGroupRule("AWSManagedRulesAmazonIpReputationList", 3),
        // 2000 requests/5min from one IP against a static SPA is already
        // generous for a real visitor (the app itself makes far fewer
        // distinct CloudFront requests per page load); tune down once
        // there's real traffic data.
        rateLimitRule(4, 2000),
      ],
    });

    this.webAclArn = acl.attrArn;
    new CfnOutput(this, "WebAclArn", { value: this.webAclArn });
  }
}

export interface NettleWafApiStackProps extends StackProps {
  /** Nettle-Api's App Runner service ARN — `service.attrServiceArn` (not attrServiceUrl) from api-stack.ts. */
  apiServiceArn: string;
}

/**
 * WAF for Nettle-Api's App Runner service. The two managed rule groups
 * most likely to false-positive against this API's own legitimate traffic
 * (scan findings/remediation text, which routinely contains the exact
 * code patterns these rules exist to catch — see countOnlyManagedRuleGroupRule's
 * own comment) run in COUNT mode; the rest run in BLOCK mode.
 */
export class NettleWafApiStack extends Stack {
  public readonly webAclArn: string;

  constructor(scope: Construct, id: string, props: NettleWafApiStackProps) {
    super(scope, id, props);

    const acl = new CfnWebACL(this, "ApiWebAcl", {
      name: "nettle-api-waf",
      scope: "REGIONAL",
      defaultAction: { allow: {} },
      visibilityConfig: {
        sampledRequestsEnabled: true,
        cloudWatchMetricsEnabled: true,
        metricName: "nettle-api-waf",
      },
      // App Runner's default inspectable request body size is 16 KB
      // (associationConfig below, matching that default explicitly rather
      // than leaving it implicit) — /api/scans's 25 MB zip uploads are far
      // beyond any reasonable inspection size regardless. AWS's own managed
      // rule groups inspect only the portion of the body within this limit
      // and don't treat the unseen remainder as a match by default, so this
      // doesn't block large uploads outright — but it does mean WAF's body
      // inspection is inherently partial for this endpoint, on top of the
      // COUNT-mode reasoning above.
      associationConfig: {
        requestBody: {
          APP_RUNNER_SERVICE: { defaultSizeInspectionLimit: "KB_16" },
        },
      },
      rules: [
        managedRuleGroupRule("AWSManagedRulesKnownBadInputsRuleSet", 1),
        countOnlyManagedRuleGroupRule("AWSManagedRulesCommonRuleSet", 2),
        countOnlyManagedRuleGroupRule("AWSManagedRulesSQLiRuleSet", 3),
        managedRuleGroupRule("AWSManagedRulesAmazonIpReputationList", 4),
        // Higher than the frontend's — this single ACL covers every
        // authenticated dashboard request, scan submission, and CI/CD
        // integration call the API receives, not just page-load traffic.
        rateLimitRule(5, 5000),
      ],
    });

    this.webAclArn = acl.attrArn;

    new CfnWebACLAssociation(this, "ApiWebAclAssociation", {
      resourceArn: props.apiServiceArn,
      webAclArn: acl.attrArn,
    });

    new CfnOutput(this, "WebAclArn", { value: this.webAclArn });
  }
}
