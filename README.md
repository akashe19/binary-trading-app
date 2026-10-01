# Binary options platform (honest settlement)

**Run:** `cp .env.example .env` (fill in) → `npm install` → `npm start`. Needs Node 18+ and PostgreSQL; the schema and admin account are created on startup. Trader UI: `/`, admin: `/admin`.

**How settlement works:** the stake is deducted when the trade opens (open price = Binance spot at that moment). A 1s worker settles expired trades against the Binance spot price: Call wins if close > open, Put if close < open, ties refund the stake. A win pays stake × (1 + payout%); a loss keeps the stake as the platform fee. The payout % is snapshotted per trade. There is no per-user or per-trade outcome override, by design. Every balance change writes a `ledger` row and every trade stores its open/close price.

**Payments:** set `NOWPAYMENTS_API_KEY` / `NOWPAYMENTS_IPN_SECRET`, and set your Binance deposit address as the payout wallet in the NOWPayments dashboard. The IPN webhook (`/api/ipn/nowpayments`) is signature-checked and credits idempotently. Manual deposits/withdrawals go to the admin queue; withdrawals are held from the balance on request and refunded on rejection.

**Before real money:** put it behind HTTPS, add email verification/KYC/AML, a CSP, and withdrawal limits, and check licensing: binary options are banned or restricted for retail users in many jurisdictions. Chart data is client-side from Binance; prices for settlement are server-side from Binance (swap `price()` for Twelve Data if needed; Binance is blocked in some regions).
