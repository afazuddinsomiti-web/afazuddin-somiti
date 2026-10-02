# আফাজউদ্দীন সমবায় সমিতি ও সংগঠন — Final Cloudflare Worker + D1

Final mobile-first public-view / admin-management app for **আফাজউদ্দীন সমবায় সমিতি ও সংগঠন**.

## Included in this version

- Public dashboard; no member login required
- Admin-only login and editing
- Flexible member count — no fixed 50-member limit
- Manual share count — any positive whole number
- ৳500 monthly contribution per share
- ৳50/share late fine after the 15th for unpaid shares (display/calculation policy)
- Dashboard: Total Collection, Total Pending, Total Should Be, Total Fine, Fund Balance
- Fund Summary: Current Month / Last 3 Months / Lifetime
- Members, Monthly Collection, Fund, Reports, and **সমিতির রুলস** pages
- Mobile-first responsive UI
- User-supplied logo used as header branding and PWA/app icon
- PWA manifest and installable icon sizes
- Cloudflare Worker + D1 backend
- Server-side session authentication using HttpOnly Secure cookie
- Admin initial password loaded from `ADMIN_INITIAL_PASSWORD` Worker Secret
- Audit log
- D1 migration for flexible share counts

## Cloudflare resources

- Worker: `falling-snow-05a0`
- D1: `afazuddin-somiti-db`
- D1 ID: `40a6c98b-daa0-43c0-b232-b519a824930b`
- D1 binding: `DB`
- Static asset binding: `ASSETS`

## Deployment

The repository is designed for Cloudflare Workers Builds with GitHub. Set the production branch to `main`; pushes to that branch should trigger a build/deploy when Workers Builds is connected.

Deploy command:

```text
npx wrangler deploy
```

Database migration command (only when needed for a new migration):

```text
npx wrangler d1 migrations apply afazuddin-somiti-db --remote
```

Before first admin login, configure the Worker Secret:

```text
ADMIN_INITIAL_PASSWORD
```

The admin email defaults to:

```text
afazuddinsomiti@gmail.com
```

After first login, use the password-change flow and use a strong unique password. Never commit a password or API token to GitHub.

## Important

Do not upload the ZIP itself to the repository. Upload/replace the files and folders inside the ZIP at the repository root so the structure remains:

- `migrations/`
- `public/`
- `src/`
- `package.json`
- `wrangler.jsonc`

The existing D1 data should be preserved; the flexible-members migration copies existing members into the new table with any positive share count.
