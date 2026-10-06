# Setup — important

The existing UI previously stored data in browser localStorage and used a client-side demo password. That is NOT production-safe.

This Cloudflare version uses D1 and server-side sessions. Before making the app public, create the admin password as a Worker secret and initialize the admin account. Do not put the real password in `index.html`, JavaScript, SQL, or Git.

Recommended secret names:
- `ADMIN_EMAIL` = `afazuddinsomiti@gmail.com` (can also be a non-secret variable)
- `ADMIN_INITIAL_PASSWORD` = a strong unique password, 14+ characters

After deployment, the first successful admin login should force a password change and the initial secret should be removed/rotated.

The API is designed for:
- GET `/api/state`
- POST `/api/login`
- POST `/api/logout`
- POST `/api/change-password`
- POST `/api/members`
- POST `/api/payments`
- POST `/api/committee`
- DELETE `/api/committee/:id`
- POST `/api/fund`
- DELETE `/api/fund/:id`

Public routes only expose read data. Mutating routes require a valid server-side session.


## Committee
The committee directory is stored in the `committee_members` D1 table. It has three sections: `board`, `executive`, and `advisory`. Committee photos are compressed in the browser and stored with the committee record, so they remain available after refresh. Committee mutations require the existing server-side admin session.
