import { sendEmail } from "./email";

/**
 * Delivery boundary for organization-invitation links — the same shared
 * SES transport as password-reset delivery (notifications/email.ts), not
 * a second email system. Set EMAIL_FROM_ADDRESS and
 * APP_ORGANIZATION_INVITE_URL to enable this; until both are set,
 * deliverInvitationLink resolves to `delivered: false` and the caller
 * (routes/organizations.routes.ts) still responds as if the invitation
 * were created — the invitation row and its token are real either way, an
 * owner just has to relay the token some other way if delivery isn't
 * configured. IMPLEMENTED — LIVE DELIVERY UNVERIFIED: the SES call is
 * real, exercised in tests against a mocked SES client; no verified
 * sending identity or live AWS credentials exist in this sandbox to send
 * an actual email.
 */

export interface InvitationDelivery {
  delivered: boolean;
  reason?: string;
}

function isDeliveryConfigured(): boolean {
  return Boolean(process.env.EMAIL_FROM_ADDRESS && process.env.APP_ORGANIZATION_INVITE_URL);
}

export async function deliverInvitationLink(
  email: string,
  token: string,
  organizationName: string,
  inviterEmail: string
): Promise<InvitationDelivery> {
  if (!isDeliveryConfigured()) {
    // Unlike password reset, the recipient's address here is already known
    // to the inviter (they typed it in), so there's no enumeration concern
    // in logging that delivery was skipped — the token itself still never
    // is.
    console.warn(
      `[org-invitation] delivery skipped for ${organizationName}: no email provider configured ` +
        "(set EMAIL_FROM_ADDRESS and APP_ORGANIZATION_INVITE_URL)"
    );
    return { delivered: false, reason: "no_provider_configured" };
  }

  const acceptUrl = `${process.env.APP_ORGANIZATION_INVITE_URL}?token=${encodeURIComponent(token)}`;

  await sendEmail({
    to: email,
    subject: `${inviterEmail} invited you to join ${organizationName} on Nettle`,
    text:
      `${inviterEmail} invited you to join "${organizationName}" on Nettle.\n\n` +
      `Accept the invitation: ${acceptUrl}\n\n` +
      `This link expires in 7 days and can only be used once. You'll need a Nettle account with this email address (${email}) to accept it.`,
    html:
      `<p>${inviterEmail} invited you to join "${organizationName}" on Nettle.</p>` +
      `<p><a href="${acceptUrl}">Accept the invitation</a></p>` +
      `<p>This link expires in 7 days and can only be used once. You'll need a Nettle account with this email address (${email}) to accept it.</p>`,
  });

  return { delivered: true };
}
