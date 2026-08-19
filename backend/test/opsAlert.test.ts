import { test } from "node:test";
import assert from "node:assert/strict";
import {
  sendOpsAlert,
  opsAlertingConfigured,
  recordOpsFailure,
  _resetOpsFailureWindowsForTests,
} from "../src/observability/opsAlert";
import type { SafeFetchResult } from "../src/scanner/ssrfSafeFetch";

function withEnv<T>(vars: Record<string, string | undefined>, fn: () => T | Promise<T>): Promise<T> {
  const saved: Record<string, string | undefined> = {};
  for (const key of Object.keys(vars)) saved[key] = process.env[key];
  for (const [key, value] of Object.entries(vars)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  return Promise.resolve(fn()).finally(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

const fakeResult: SafeFetchResult = {
  statusCode: 200,
  headers: {},
  body: "ok",
  finalUrl: "http://example.invalid/hook",
  redirectChain: [],
  tls: null,
};

test("opsAlertingConfigured is false when neither channel is set", async () => {
  await withEnv({ NETTLE_OPS_ALERT_WEBHOOK_URL: undefined, NETTLE_OPS_ALERT_EMAIL: undefined }, () => {
    assert.equal(opsAlertingConfigured(), false);
  });
});

test("sendOpsAlert is a real no-op when unconfigured — it does not throw, and delivers nothing", async () => {
  await withEnv({ NETTLE_OPS_ALERT_WEBHOOK_URL: undefined, NETTLE_OPS_ALERT_EMAIL: undefined }, async () => {
    let called = false;
    await sendOpsAlert({ category: "unhandled_exception", message: "should be a no-op" }, async () => {
      called = true;
      return fakeResult;
    });
    assert.equal(called, false, "no fetcher call should happen when nothing is configured");
  });
});

test("sendOpsAlert posts the alert to the configured webhook URL with the right shape", async () => {
  await withEnv({ NETTLE_OPS_ALERT_WEBHOOK_URL: "https://example.invalid/hook", NETTLE_OPS_ALERT_EMAIL: undefined }, async () => {
    let receivedUrl: string | null = null;
    let receivedBody: any = null;
    await sendOpsAlert(
      { category: "startup_failure", message: "the backend did not start", detail: "stack trace here" },
      async (url, opts) => {
        receivedUrl = url;
        receivedBody = JSON.parse(opts.body);
        return fakeResult;
      }
    );

    assert.equal(receivedUrl, "https://example.invalid/hook");
    assert.equal(receivedBody.category, "startup_failure");
    assert.equal(receivedBody.message, "the backend did not start");
    assert.match(receivedBody.text, /startup_failure/);
  });
});

test("sendOpsAlert never throws even when webhook delivery itself throws", async () => {
  await withEnv({ NETTLE_OPS_ALERT_WEBHOOK_URL: "https://example.invalid/hook", NETTLE_OPS_ALERT_EMAIL: undefined }, async () => {
    await assert.doesNotReject(() =>
      sendOpsAlert({ category: "unhandled_exception", message: "test" }, async () => {
        throw new Error("simulated delivery failure");
      })
    );
  });
});

test("recordOpsFailure does not alert below the threshold", () => {
  _resetOpsFailureWindowsForTests();
  let calls = 0;
  recordOpsFailure("stripe_webhook_failures", "isolated failure", undefined, 5, async () => {
    calls += 1;
  });
  recordOpsFailure("stripe_webhook_failures", "isolated failure", undefined, 5, async () => {
    calls += 1;
  });
  assert.equal(calls, 0, "two failures under a threshold of 5 must not alert");
});

test("recordOpsFailure alerts exactly once the threshold is crossed, then goes quiet for the cooldown", () => {
  _resetOpsFailureWindowsForTests();
  let calls = 0;
  const alertFn = async () => {
    calls += 1;
  };

  for (let i = 0; i < 3; i++) recordOpsFailure("stripe_webhook_failures", "sustained failure", undefined, 3, alertFn);
  assert.equal(calls, 1, "crossing the threshold should fire exactly one alert");

  for (let i = 0; i < 5; i++) recordOpsFailure("stripe_webhook_failures", "still failing", undefined, 3, alertFn);
  assert.equal(calls, 1, "repeated failures inside the cooldown window must not re-alert");
});

test("recordOpsFailure tracks categories independently", () => {
  _resetOpsFailureWindowsForTests();
  let stripeCalls = 0;
  let rejectionCalls = 0;

  for (let i = 0; i < 3; i++) {
    recordOpsFailure("stripe_webhook_failures", "a", undefined, 3, async () => {
      stripeCalls += 1;
    });
  }
  assert.equal(stripeCalls, 1);
  assert.equal(rejectionCalls, 0);

  recordOpsFailure("unhandled_rejection", "b", undefined, 1, async () => {
    rejectionCalls += 1;
  });
  assert.equal(rejectionCalls, 1, "a different category's own threshold must not be affected by stripe's count");
});
