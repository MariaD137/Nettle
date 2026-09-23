import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";

/**
 * The single seam where this codebase actually talks to an email provider.
 * Password-reset delivery and organization-invitation delivery both go
 * through this — one shared, tested transport, not two unrelated email
 * systems (see notifications/passwordResetDelivery.ts and
 * notifications/invitationDelivery.ts, which are policy/content wrappers
 * around this, not separate senders).
 *
 * SES v2 (`@aws-sdk/client-sesv2`) is the AWS-native fit for this stack —
 * same reasoning as using RDS over a third-party DB host, or Secrets
 * Manager over a third-party vault: it's already the surrounding
 * infrastructure's own cloud, needs no new vendor relationship, and
 * authenticates via the exact same IAM role / credential chain every other
 * AWS SDK call in this codebase already uses (see billing/stripeClient.ts
 * for the equivalent lazy-init pattern with a third-party API instead).
 *
 * No credentials are read or hardcoded here — the SDK's default credential
 * provider chain resolves them from the environment (IAM role on App
 * Runner in production; local AWS CLI config / env vars in development),
 * exactly like every other AWS SDK client. A raw AWS credential never
 * appears anywhere in this repo.
 */

interface MinimalSesClient {
  send(command: SendEmailCommand): Promise<unknown>;
}

let client: SESv2Client | null = null;
let clientOverride: MinimalSesClient | null = null;

function getSesClient(): MinimalSesClient {
  if (clientOverride) return clientOverride;
  if (!client) {
    client = new SESv2Client({});
  }
  return client;
}

/**
 * Test-only seam: injects a fake SES client so sendEmail() can be exercised
 * without a real network call or live AWS credentials — this codebase has
 * no HTTP-mocking library, and adding one for a single client would be a
 * bigger addition than this narrow override. Pass null to restore the real
 * lazily-constructed client.
 */
export function _setSesClientForTesting(fake: MinimalSesClient | null): void {
  clientOverride = fake;
}

export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

/**
 * Sends one transactional email via SES. Throws on any configuration or
 * delivery failure rather than swallowing it — callers (passwordResetDelivery,
 * invitationDelivery) decide how to handle that without this function ever
 * pretending a failed send succeeded.
 */
export async function sendEmail(message: EmailMessage): Promise<void> {
  const fromAddress = process.env.EMAIL_FROM_ADDRESS;
  if (!fromAddress) {
    throw new Error("EMAIL_FROM_ADDRESS is not set — SES delivery is not configured in this environment");
  }

  const ses = getSesClient();
  await ses.send(
    new SendEmailCommand({
      FromEmailAddress: fromAddress,
      Destination: { ToAddresses: [message.to] },
      Content: {
        Simple: {
          Subject: { Data: message.subject, Charset: "UTF-8" },
          Body: {
            Text: { Data: message.text, Charset: "UTF-8" },
            ...(message.html ? { Html: { Data: message.html, Charset: "UTF-8" } } : {}),
          },
        },
      },
    })
  );
}
