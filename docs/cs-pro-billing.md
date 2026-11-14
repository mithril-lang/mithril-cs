# CS Pro billing — MITHRIL-2517

This is a separate product from Fund service tokens and Agent Pro. Merchant:
Kotoba Labs, Inc., `acct_1U7sRyITDawH5x8a`. Price: USD29 per month for one
authenticated personal seat. No trial, coupon, overage or quantity change.
Existing free-pilot permissions and engine/target limits are preserved.

Provisioned live Product: `mithril_cs_pro_v1`; monthly Price:
`price_1Ubey0ITDawH5x8a3YgpaG7t`; Portal configuration:
`bpc_1Ubf06ITDawH5x8a61JGTcye`. Product tax code `txcd_10103001`
(business SaaS) was explicitly confirmed by Jun. These objects alone do not
enable acquisition or establish payment acceptance.

Dedicated development Sandbox: `acct_1Ubf2TIJVnMCo3dC`,
`Mithril CS Development`, created without copying production data. The core
adapter pins this account in isolated test mode; the production entrypoint
continues to reject all test-mode requests.

This empty Sandbox reports `charges_enabled=false` but successfully created
an unpaid test hosted Checkout with the exact monthly Price and automatic
tax. The live merchant still must report `charges_enabled=true`. Sandbox Tax
settings use a synthetic address and New Jersey fixture registration solely
to test collection; no real merchant registration is implied or modified.

The owner-side `tools/stripe_sandbox_verify.mjs` reads protected, temporary
Sandbox credentials and resource IDs from `CS_SANDBOX_STATE`, requires an
exact `CS_SOURCE_SHA`, and binds an HTTP listener to loopback only. It calls
the real adapter and Stripe API and accepts signed provider notifications
forwarded by the Stripe CLI. It refuses live keys and any other account.
Its synthetic owner is separate from actual Mithril authentication. This
qualifies provider behavior only, not production login or public webhook
delivery. Do not run this controller in VKE, PR jobs or a public Worker.

Design: Figma file `N42vvZ2M7tgH2IkGXUUOWP`, section `1057:46215`.
Sixteen desktop states cover Grid/Porcelain, with two mobile examples. Card
entry belongs to hosted Stripe Checkout; card data never reaches this Worker.

## Authority and state

Existing Mithril identity identifies the payer on every operation. Personal
billing is isolated from organization/Project authority. POST uses the existing
Origin/CSRF contract. The browser checks the session scope again before a
redirect. Browser amounts, customer IDs and redirect URLs are never accepted.

Stripe is the authority for money and subscription state; D1 is a scoped cache,
consent receipt and reconciliation journal. Success/cancel return parameters
never grant access. Subscription, latest paid invoice, price, customer, mode,
metadata, period end and risk holds are checked. Immutable terms receipts bind
the authenticated actor, operation, terms version, source and time. Checkout
and customer creation reuse stable provider idempotency keys. A lost outcome
older than23hours is held for owner reconciliation, not charged again.

Concurrent provider reads use a verification token. An older writer cannot
overwrite a newer provider observation. Refund, dispute and early fraud events
set a monotonic hold; later paid notifications cannot clear it. Clearing a
confirmed hold requires an independently reviewed owner recovery procedure,
which is not implemented by the customer portal. Existing results remain held
by their original owner; this work deletes no records.

## Live configuration gate

The public Pro CTA remains the existing inquiry unless
`CS_BILLING_PUBLIC_CHECKOUT=true`, `CS_BILLING_TAX_READY=true` and the runtime
key is present. Merely setting flags is not qualification: authenticated
Checkout also rechecks the merchant, USD2900 licensed monthly Price, its active
CS Product and tax code, and current active tax registrations.

Required private Worker secrets:

- `STRIPE_CS_KEY`: dedicated restricted LIVE key for the above merchant.
- `STRIPE_CS_WEBHOOK_SECRET`: signing secret for this exact endpoint/account.

Required non-secret configuration:

- `CS_BILLING_MODE=live`.
- `STRIPE_CS_PRICE`: fixed active Price ID; Product metadata
  `service=mithril-cs-pro-v1`, verified software tax code, USD2900, monthly,
  quantity1. No other plan is reused.
- `STRIPE_CS_PORTAL_CONFIG`: dedicated active configuration with matching
  service metadata; invoice history and payment-method update enabled;
  cancellation enabled at period end; subscription/quantity updates disabled.
- `CS_BILLING_TAX_READY=true` only after the merchant confirms and verifies
  applicable registrations and a calculation/preview in the target market.

Use 1Password and the qualified Worker owner to project credentials without
printing them or placing them in a PR job. Prefer a restricted key limited to
Customer write, Checkout Session write, Subscription/Invoice/Price/Product/
Charge/Tax Registration reads, Customer Portal Session write and Portal
Configuration read. No payout, transfer, bank, refund-write or key-admin
permissions belong in the CS Worker. Verify the actual key's required access
and denial of unrelated operations in the isolated environment before live use.

Apply the additive schema before publishing the module. Preserve all existing
rows, backups and provider state; no owner or store migration is involved.
Production entrypoint rejects test mode even if an isolated-test marker is set.
The core adapter allows an explicitly isolated test fixture, not a production
test-key switch. Use a separate Stripe Sandbox and separate private controller
and database for real provider tests; never project credentials into VKE PR Pods.

## Webhook contract

Endpoint: `https://cs.mithril.fund/api/billing/webhook`. Require a raw-body
HMAC-SHA256 Stripe signature (300second age,30second future clock allowance),
matching mode and bounded256KiB payload. The event ledger deduplicates processed
IDs. Failed/unknown processing returns a failure so Stripe can retry; no raw
card/customer payload is retained in Git or the event ledger.

Subscribe only to the events this adapter acts on:

- checkout.session.completed, checkout.session.async_payment_succeeded
- customer.subscription.created, updated, deleted
- invoice.paid, invoice.payment_failed
- charge.refunded, charge.dispute.created, radar.early_fraud_warning.created

Subscription status is read from Stripe rather than applied from a potentially
out-of-order event snapshot. Customer profile/name/address data are not copied
locally, so customer.updated is not required for a local profile cache.

## Required qualification and remaining gates

VKE runs original JVM/CLJS/BB and edge cases plus financial fixtures, without
real credentials. Cases include concurrent duplicate Checkout, ambiguous
outcome/retry/retention, merchant/price/seat/mode/invoice mismatch, stale writers,
webhook forgery/replay/order/risk, cancellation, actor/CSRF and paid export.
These do not establish hosted-provider or actual customer payment acceptance.

Real Sandbox verification must cover Checkout/card challenge/decline/abandon,
signed webhook delivery and retries, activation, renewal, payment failure,
portal cancellation/reactivation, refund/dispute/risk and owner isolation.
After exact-source main/provider readback, enable live only when those gates
and merchant/tax/fulfillment authority are confirmed. A real live charge must
be performed by the account owner on the final Stripe payment screen.

Observed2026-11-14: live CS credentials are not configured; available local
CLI/key contexts belong to other merchants and must not be used. Tax settings
are active but active registrations are empty. Delaware incorporation is not
proof of sales-tax registration: Delaware's Division of Revenue states it has
no state/local sales tax and separately describes gross-receipts tax. Do not
create a fictional Delaware sales-tax registration or infer other jurisdictions.

Evidence/remaining decisions: MITHRIL-2517. Full managed-engine and organization
service acceptance remain with their existing owners. No live subscription,
tax collection, real card payment or complete service rollout is claimed here.
