# Saved reports + login (Supabase) — 5-minute setup

VibeScan now persists every scan and supports passwordless (magic-link) login.
**It works with zero setup** — without Supabase keys it stays a free one-shot
scanner. Add the keys below to turn on saved reports, `/r/{id}` links, and accounts.

## 1. Create a Supabase project (free)

1. Go to <https://supabase.com> → **New project**. Pick a region near you.
2. Wait ~1 minute for it to provision.

## 2. Create the `scans` table

1. In the project: **SQL Editor → New query**.
2. Paste the contents of [`supabase/schema.sql`](supabase/schema.sql) and click **Run**.

## 3. Copy your keys into `.env`

In Supabase: **Settings → API**. Copy these into the repo-root `.env`:

```env
NEXT_PUBLIC_SUPABASE_URL=https://YOURPROJECT.supabase.co   # "Project URL"
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...                        # "anon public" key
SUPABASE_SERVICE_ROLE_KEY=eyJ...                            # "service_role" key — keep secret!
# In production set your real origin so magic links point to the right place:
# NEXT_PUBLIC_SITE_URL=https://yourdomain.com
```

> The `service_role` key has full database access. It is only read by server-side
> code (it has no `NEXT_PUBLIC_` prefix) and must never be committed or shipped to
> the browser. `.env` is already gitignored.

## 4. Point magic links back to the app

In Supabase: **Authentication → URL Configuration**:

- **Site URL**: `http://localhost:3000` (and your production URL when you deploy).
- **Redirect URLs**: add `http://localhost:3000/auth/confirm`
  (and `https://yourdomain.com/auth/confirm` in production).

That's it. Restart `npm run dev` so the new env is picked up.

## 5. Enable Google and GitHub sign-in (optional but recommended)

No extra env vars — OAuth providers are configured in the Supabase dashboard, and
both providers reuse the **same** `/auth/confirm` redirect the magic link uses.

In Supabase: **Authentication → Providers**:

**Google**

1. In [Google Cloud Console](https://console.cloud.google.com/apis/credentials):
   **Create credentials → OAuth client ID → Web application**.
2. Add **Authorized redirect URI**: `https://<YOURPROJECT>.supabase.co/auth/v1/callback`
   (copy the exact callback URL shown on Supabase's Google provider page).
3. Paste the **Client ID** and **Client secret** into Supabase's Google provider and enable it.

**GitHub**

1. In GitHub: **Settings → Developer settings → OAuth Apps → New OAuth App**.
2. **Authorization callback URL**: `https://<YOURPROJECT>.supabase.co/auth/v1/callback`.
3. Paste the **Client ID** and **Client secret** into Supabase's GitHub provider and enable it.

The app's own redirect (`/auth/confirm`) is already in your **Redirect URLs** from step 4,
so nothing else changes. The login page hides the Google/GitHub buttons until Supabase
keys are present.

## What you get

| Route            | What it does                                                        |
| ---------------- | ------------------------------------------------------------------- |
| `/r/{id}`        | Permanent, shareable report — survives closing the tab.             |
| `/login`         | Continue with Google/GitHub, or get a one-click email link.         |
| `/dashboard`     | Your scan history (only your own rows, enforced by RLS).            |
| `/account`       | Profile name, connected sign-in methods, delete account.            |
| **Copy link** button on every report | Grabs the `/r/{id}` URL to share.              |

Scans run while **signed in** are attached to your account and show in the
dashboard. Scans run **logged out** are still saved and shareable by link, just
not tied to a user.

## Notes & next steps (the foundation for items 3–10)

- This is the persistence layer monitoring, scheduled re-scans, alerts and billing
  build on: every scan is a row in `scans` with `user_id`, `score`, `verdict`,
  timestamps and the full result JSON.
- **Magic-link email template (optional):** the default works out of the box via
  the PKCE `?code=` flow. If you switch Supabase's email template to use
  `{{ .TokenHash }}`, the `/auth/confirm` route already handles `token_hash` too.
- **Email sending:** Supabase's built-in mailer is rate-limited (a few/hour) and
  fine for testing. For production, add an SMTP provider in
  **Authentication → Emails → SMTP Settings** (e.g. Resend, Postmark).
