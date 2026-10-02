# আফাজউদ্দীন সমবায় সমিতি ও সংগঠন — Cloudflare Worker + D1

This project is prepared as a full-stack Cloudflare Worker with static assets and a D1 binding.

## Cloudflare resources
- Worker: `falling-snow-05a0`
- D1: `afazuddin-somiti-db`
- D1 ID: `40a6c98b-daa0-43c0-b232-b519a824930b`
- D1 binding: `DB`

## Important
The Wrangler config is the source of truth. Deploy this project with Wrangler or connect the folder/repository through Workers Builds. Cloudflare currently recommends a `main` Worker script together with `assets.directory` for full-stack Workers.

## First deployment
1. Install Node.js 20+.
2. In this folder run: `npm install`
3. Run: `npx wrangler login`
4. Run: `npx wrangler d1 migrations apply afazuddin-somiti-db --remote`
5. Set the initial admin secret/password through Cloudflare Worker Secrets before deployment. See `SETUP.md`.
6. Run: `npx wrangler deploy`

## Note
The supplied front-end is the existing visual design. The next integration step is to switch its data layer from browser storage to the `/api/*` Worker endpoints. This package contains the secure D1 schema and Worker foundation; do not treat the old browser-only login as production authentication.
