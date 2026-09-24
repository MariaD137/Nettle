// SES email delivery (master spec Phases 3/11/12): notifications/email.ts
// is the one shared transport for both password-reset and organization-
// invitation delivery. No live AWS credentials exist in this sandbox, so
// these tests exercise the real code path — configuration validation,
// content construction, and the actual SendEmailCommand this codebase
// would issue — against an injected fake SES client (see email.ts's
// _setSesClientForTesting), not a live network call. That is real coverage
// of "does this codebase call SES correctly", not "was an email actually
// delivered" — the honest distinction the final report keeps.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { SendEmailCommand } from "@aws-sdk/client-sesv2";
import { sendEmail, _setSesClientForTesting } from "../src/notifications/email";
import { deliverPasswordResetLink } from "../src/notifications/passwordResetDelivery";
import { deliverInvitationLink } from "../src/notifications/invitationDelivery";

const ORIGINAL_ENV = { ...process.env };

afterEach(() => {
  _setSesClientForTesting(null);
  process.env = { ...ORIGINAL_ENV };
});

test("sendEmail throws a clear error when EMAIL_FROM_ADDRESS is not set", async () => {
  delete process.env.EMAIL_FROM_ADDRESS;
  await assert.rejects(
    () => sendEmail({ to: "someone@example.com", subject: "Test", text: "Test" }),
    /EMAIL_FROM_ADDRESS is not set/
  );
});

test("sendEmail issues a real SendEmailCommand with the right shape when configured", async () => {
  process.env.EMAIL_FROM_ADDRESS = "noreply@nettle.dev";
  let captured: SendEmailCommand | null = null;
  _setSesClientForTesting({
    send: async (command) => {
      captured = command as SendEmailCommand;
      return { MessageId: "test-message-id" };
    },
  });

  await sendEmail({ to: "user@example.com", subject: "Hello", text: "Body text", html: "<p>Body text</p>" });

  assert.ok(captured, "sendEmail must actually call the SES client");
  assert.ok((captured as unknown) instanceof SendEmailCommand);
  const input = (captured as SendEmailCommand).input;
  assert.equal(input.FromEmailAddress, "noreply@nettle.dev");
  assert.deepEqual(input.Destination?.ToAddresses, ["user@example.com"]);
  assert.equal(input.Content?.Simple?.Subject?.Data, "Hello");
  assert.equal(input.Content?.Simple?.Body?.Text?.Data, "Body text");
  assert.equal(input.Content?.Simple?.Body?.Html?.Data, "<p>Body text</p>");
});

test("sendEmail propagates a real SES failure rather than swallowing it", async () => {
  process.env.EMAIL_FROM_ADDRESS = "noreply@nettle.dev";
  _setSesClientForTesting({
    send: async () => {
      throw new Error("MessageRejected: Email address is not verified");
    },
  });

  await assert.rejects(
    () => sendEmail({ to: "user@example.com", subject: "Hello", text: "Body" }),
    /Email address is not verified/
  );
});

test("deliverPasswordResetLink reports delivered:false, not an error, when nothing is configured", async () => {
  delete process.env.EMAIL_FROM_ADDRESS;
  delete process.env.APP_PASSWORD_RESET_URL;
  const result = await deliverPasswordResetLink("someone@example.com", "raw-token-value");
  assert.equal(result.delivered, false);
  assert.equal(result.reason, "no_provider_configured");
});

test("deliverPasswordResetLink sends a real email with the reset link and token when configured", async () => {
  process.env.EMAIL_FROM_ADDRESS = "noreply@nettle.dev";
  process.env.APP_PASSWORD_RESET_URL = "https://app.nettle.dev/reset-password";
  let captured: SendEmailCommand | null = null;
  _setSesClientForTesting({
    send: async (command) => {
      captured = command as SendEmailCommand;
      return {};
    },
  });

  const result = await deliverPasswordResetLink("someone@example.com", "the-raw-token");
  assert.equal(result.delivered, true);
  assert.ok(captured);
  const input = (captured as SendEmailCommand).input;
  assert.equal(input.Destination?.ToAddresses?.[0], "someone@example.com");
  assert.ok(input.Content?.Simple?.Body?.Text?.Data?.includes("the-raw-token"));
  assert.ok(input.Content?.Simple?.Body?.Text?.Data?.includes("https://app.nettle.dev/reset-password"));
});

test("deliverInvitationLink reports delivered:false when nothing is configured", async () => {
  delete process.env.EMAIL_FROM_ADDRESS;
  delete process.env.APP_ORGANIZATION_INVITE_URL;
  const result = await deliverInvitationLink("invitee@example.com", "invite-token", "Acme Corp", "owner@example.com");
  assert.equal(result.delivered, false);
  assert.equal(result.reason, "no_provider_configured");
});

test("deliverInvitationLink sends a real email naming the organization and inviter when configured", async () => {
  process.env.EMAIL_FROM_ADDRESS = "noreply@nettle.dev";
  process.env.APP_ORGANIZATION_INVITE_URL = "https://app.nettle.dev/accept-invitation";
  let captured: SendEmailCommand | null = null;
  _setSesClientForTesting({
    send: async (command) => {
      captured = command as SendEmailCommand;
      return {};
    },
  });

  const result = await deliverInvitationLink("invitee@example.com", "invite-token-xyz", "Acme Corp", "owner@example.com");
  assert.equal(result.delivered, true);
  assert.ok(captured, "deliverInvitationLink must actually call the SES client");
  const input = (captured! as SendEmailCommand).input;
  assert.equal(input.Destination?.ToAddresses?.[0], "invitee@example.com");
  assert.ok(input.Content?.Simple?.Subject?.Data?.includes("Acme Corp"));
  assert.ok(input.Content?.Simple?.Body?.Text?.Data?.includes("invite-token-xyz"));
  assert.ok(input.Content?.Simple?.Body?.Text?.Data?.includes("owner@example.com"));
});
