# GitHub → Cloudflare Workers deployment

এই project-এ Worker code + static assets + D1 binding configuration আছে।

## GitHub
1. GitHub-এ নতুন repository তৈরি করুন।
2. এই folder-এর সব file repository-র root-এ upload করুন (ZIP file নয়; ZIP extract করে file upload করুন)।
3. Commit করুন।

## Cloudflare
Workers & Pages → falling-snow-05a0 → Settings → Builds → Connect.
GitHub repository ও `main` branch select করুন।

Build command: ফাঁকা রাখুন
Deploy command: `npx wrangler deploy`
Root directory: `/` বা blank

তারপর Save and Deploy.

## D1
Wrangler config-এ ইতিমধ্যে:
- Worker: falling-snow-05a0
- Database: afazuddin-somiti-db
- Database ID: 40a6c98b-daa0-43c0-b232-b519a824930b
- Binding: DB

D1 migration এখনও আলাদাভাবে চালাতে হতে পারে। Cloudflare Dashboard-এর D1 → afazuddin-somiti-db → Console-এ `migrations/0001_initial.sql`-এর SQL execute করা যাবে।

## Important
কোনো Cloudflare API token বা password এই repository-তে রাখবেন না।
