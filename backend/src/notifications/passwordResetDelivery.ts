/**
 * Delivery boundary for password-reset links.
 *
 * There is no email provider integrated in this codebase. Rather than pretend
 * otherwise, this module is the single seam where one gets wired in, and it
 * reports honestly when nothing is configured.
 *
 * What it must never do — and what it replaces — is the previous behaviour of
 * writing the reset token to stdout. On App Runner that goes straight to
 * CloudWatch, so anyone with log read access could take over any account by
 * requesting a reset for its address and reading the token out of the logs.
 *
 * To enable real delivery, implement `sendEmail` against a provider (SES is
 * the AWS-native fit for this stack) and set PASSWORD_RESET_FROM_ADDRESS plus
 * APP_PASSWORD_RESET_URL. Until then `deliverPasswordResetLink` returns
 * `false` and the caller still responds generically, so the API's behaviour
 * does not reveal whether an address is registered.
 */

export interface PasswordResetDelivery {
  delivered: boolean;
  reason?: string;
}

function isDeliveryConfigured(): boolean {
  return Boolean(process.env.PASSWORD_RESET_FROM_ADDRESS && process.env.APP_PASSWORD_RESET_URL);
}

export function deliverPasswordResetLink(email: string, token: string): PasswordResetDelivery {
  if (!isDeliveryConfigured()) {
    // Deliberately logs neither the token nor the address: the token is a
    // credential, and the address would leak who holds an account.
    console.warn(
      "[password-reset] delivery skipped: no email provider configured " +
        "(set PASSWORD_RESET_FROM_ADDRESS and APP_PASSWORD_RESET_URL, and implement sendEmail)"
    );
    return { delivered: false, reason: "no_provider_configured" };
  }

  // A provider is configured but no transport is implemented yet. Failing
  // loudly here is correct: silently returning `delivered: true` would make
  // the reset flow look healthy while no mail is ever sent.
  void email;
  void token;
  throw new Error(
    "Password-reset delivery is configured but no email transport is implemented. " +
      "Implement sendEmail() in src/notifications/passwordResetDelivery.ts."
  );
}
