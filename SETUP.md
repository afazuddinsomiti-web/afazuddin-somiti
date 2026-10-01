# Cloudflare setup — আফাজউদ্দীন সমবায় সমিতি ও সংগঠন

This project is a Cloudflare Worker + D1 application. Public pages are read-only; member/payment/fund changes require a server-side Admin session.

## Cloudflare resources
- Worker: `falling-snow-05a0`
- D1: `afazuddin-somiti-db`
- D1 ID: `40a6c98b-daa0-43c0-b232-b519a824930b`
- D1 binding: `DB`
- Admin email: `afazuddinsomiti@gmail.com`

## Deploy with Workers Builds
Use the standard deploy command:
`npx wrangler deploy`

Build command: leave blank.
Deploy command: `npx wrangler deploy`.

## D1 migration
Run once after the Worker repository is connected:
`npx wrangler d1 migrations apply afazuddin-somiti-db --remote`

If you are not using a local Node.js installation, run the migration from Cloudflare's D1 Console / dashboard SQL tools, using the SQL in `migrations/0001_initial.sql`.

## Admin secret
Before first Admin login, create a Worker secret named:
`ADMIN_INITIAL_PASSWORD`

Use a strong unique password (at least 12 characters). The first successful login forces a password change. Never put the real password in GitHub.

Optional variable:
`ADMIN_EMAIL=afazuddinsomiti@gmail.com`

## Data rules
- Share = ৳500/month
- Shares allowed: 5, 6, or 10
- Cutoff: 15th
- Fine: ৳50 per share when the share remains unpaid after the cutoff
- Fund balance is based on actual recorded fund transactions, not estimated unpaid fines.
- The first API request seeds 50 starter members only when the members table is empty.
