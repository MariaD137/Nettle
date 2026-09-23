import { sendEmail } from "./email";

/**
 * Delivery boundary for password-reset links.
 *
 * Real delivery now goes through notifications/email.ts (SES). This module
 * stays the single seam that decides *what* the reset email says and
 * *whether* delivery was even configured — it reports honestly when it
 * wasn't, rather than pretending.
 *
 * What it must never do — and what it replaces — is the previous behaviour of
 * writing the reset token to stdout. On App Runner that goes straight to
 * CloudWatch, so anyone with log read access could take over any account by
 * requesting a reset for its address and reading the token out of the logs.
 *
 * Set EMAIL_FROM_ADDRESS and APP_PASSWORD_RESET_URL to enable this. Until
 * both are set, deliverPasswordResetLink resolves to `delivered: false` and
 * the caller still responds generically, so the API's behaviour does not
 * reveal whether an address is registered. IMPLEMENTED — LIVE DELIVERY
 * UNVERIFIED: the SES call itself is real code, exercised in tests against
 * a mocked SES client, but no verified sending identity or live AWS
 * credentials exist in this sandbox to send an actual email through.
 */

export interface PasswordResetDelivery {
  delivered: boolean;
  reason?: string;
}

function isDeliveryConfigured(): boolean {
  return Boolean(process.env.EMAIL_FROM_ADDRESS && process.env.APP_PASSWORD_RESET_URL);
}

export async function deliverPasswordResetLink(email: string, token: string): Promise<PasswordResetDelivery> {
  if (!isDeliveryConfigured()) {
    // Deliberately logs neither the token nor the address: the token is a
    // credential, and the address would leak who holds an account.
    console.warn(
      "[password-reset] delivery skipped: no email provider configured " +
        "(set EMAIL_FROM_ADDRESS and APP_PASSWORD_RESET_URL)"
    );
    return { delivered: false, reason: "no_provider_configured" };
  }

  const resetUrl = `${process.env.APP_PASSWORD_RESET_URL}?token=${encodeURIComponent(token)}`;

  await sendEmail({
    to: email,
    subject: "Reset your Nettle password",
    text:
      `A password reset was requested for your Nettle account.\n\n` +
      `Reset your password: ${resetUrl}\n\n` +
      `This link expires in 1 hour and can only be used once. If you didn't request this, you can ignore this email — your password will not change.`,
    html:
      `<p>A password reset was requested for your Nettle account.</p>` +
      `<p><a href="${resetUrl}">Reset your password</a></p>` +
      `<p>This link expires in 1 hour and can only be used once. If you didn't request this, you can ignore this email — your password will not change.</p>`,
  });

  return { delivered: true };
}
