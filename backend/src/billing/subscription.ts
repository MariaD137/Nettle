// This module is kept as a stable import path for existing callers.
// The actual entitlement logic — the single authoritative mechanism every
// paid feature must use — lives in ./entitlement. Do not reimplement plan
// or subscription-status checks here or anywhere else.
export { hasPaidEntitlement as hasActiveSubscription, requireSubscription, PAID_PLANS } from "./entitlement";
