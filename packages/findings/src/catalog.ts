import type { Category, CodeExample, FindingType, Platform, Severity } from './types';

export interface CatalogEntry {
  /** Short human title shown on the report card. */
  title: string;
  category: Category;
  /** Default severity; a finding instance may override it. */
  defaultSeverity: Severity;
  /** Plain-language, no-jargon explanation of why this matters to a non-technical founder. */
  whatItMeans: string;
  /**
   * The core remediation ask, phrased as an instruction. We wrap it with a
   * platform-specific prefix (see PLATFORM_META) to build the copy-paste prompt
   * for any AI builder — Lovable, Bolt, Replit, Base44, v0, Cursor, …
   * May contain {{placeholders}} filled from finding.params.
   */
  fixInstruction: string;
  /** Step-by-step manual fix — the platform-agnostic ("generic") track. */
  fixSteps: string;
  /** Optional per-platform overrides where a builder needs special wording. */
  fixOverrides?: Partial<Record<Platform, string>>;
  /** Developed, copy-pasteable code samples per stack — the "real code" companion to the prompt. */
  codeExamples?: CodeExample[];
}

/** Display label + prompt prefix for each supported builder. */
export const PLATFORM_META: Record<Platform, { label: string; promptPrefix: string }> = {
  lovable: { label: 'Lovable', promptPrefix: 'Paste this into Lovable chat:' },
  bolt: { label: 'Bolt', promptPrefix: 'Paste this into Bolt:' },
  replit: { label: 'Replit', promptPrefix: 'Paste this into Replit AI (Agent):' },
  base44: { label: 'Base44', promptPrefix: 'Paste this into Base44 chat:' },
  v0: { label: 'v0', promptPrefix: 'Paste this into v0:' },
  cursor: { label: 'Cursor', promptPrefix: 'Paste this into Cursor (⌘K / chat):' },
  generic: { label: 'Other / generic', promptPrefix: '' },
};

/** Platforms in display order — drives the report's "Show fix for:" selector. */
export const PLATFORMS: { id: Platform; label: string }[] = (
  ['lovable', 'bolt', 'replit', 'base44', 'v0', 'cursor', 'generic'] as Platform[]
).map((id) => ({ id, label: PLATFORM_META[id].label }));

/**
 * The product's voice lives here. Every finding type maps to one entry so the
 * scanner stays lean (it only tags a `type`) and the UI explains it consistently.
 */
export const CATALOG: Record<FindingType, CatalogEntry> = {
  secret_exposed: {
    title: 'Secret API key exposed in your code',
    category: 'secrets',
    defaultSeverity: 'critical',
    whatItMeans:
      "A private key ({{provider}}) is visible in your site's public JavaScript. Anyone who opens your site can copy it and use it as you — spend money, send emails, or read your data. Keys like this must live on a server, never in the browser.",
    fixInstruction:
      'There is a {{provider}} secret key hard-coded in my frontend code. Move it to a server-side environment variable (a serverless/edge function or backend route) and call that function from the app instead of calling the third-party API directly from the browser. Remove the key from all client code. After that, I will rotate the key in the provider dashboard.',
    fixSteps:
      '1) Rotate (regenerate) the {{provider}} key now — assume it is compromised. 2) Move it out of frontend code into a server environment variable. 3) Call the third-party API from your backend, never directly from the browser.',
    codeExamples: [
      {
        stack: 'Supabase Edge Function',
        language: 'ts',
        note: 'Keep the key server-side; the browser calls your function, never the provider.',
        code: `// supabase/functions/call-provider/index.ts
import "jsr:@supabase/functions-js/edge-runtime.d.ts";

Deno.serve(async (req) => {
  const apiKey = Deno.env.get("PROVIDER_API_KEY"); // set with: supabase secrets set PROVIDER_API_KEY=...
  if (!apiKey) return new Response("Misconfigured", { status: 500 });

  const { prompt } = await req.json();
  const res = await fetch("https://api.provider.com/v1/do", {
    method: "POST",
    headers: { authorization: \`Bearer \${apiKey}\`, "content-type": "application/json" },
    body: JSON.stringify({ prompt }),
  });
  return new Response(await res.text(), {
    headers: { "content-type": "application/json" },
  });
});`,
      },
      {
        stack: 'Next.js (App Router)',
        language: 'ts',
        note: 'A server route holds the key; the client fetches the route, not the provider.',
        code: `// app/api/provider/route.ts  — runs only on the server
import { NextResponse } from "next/server";

export async function POST(req: Request) {
  const { prompt } = await req.json();
  const res = await fetch("https://api.provider.com/v1/do", {
    method: "POST",
    headers: {
      authorization: \`Bearer \${process.env.PROVIDER_API_KEY}\`, // .env.local, never NEXT_PUBLIC_*
      "content-type": "application/json",
    },
    body: JSON.stringify({ prompt }),
  });
  return NextResponse.json(await res.json());
}

// In the browser: fetch("/api/provider", { method: "POST", body: JSON.stringify({ prompt }) })`,
      },
      {
        stack: 'Express / Node',
        language: 'ts',
        code: `// server.ts
import express from "express";
const app = express();
app.use(express.json());

app.post("/api/provider", async (req, res) => {
  const r = await fetch("https://api.provider.com/v1/do", {
    method: "POST",
    headers: {
      authorization: \`Bearer \${process.env.PROVIDER_API_KEY}\`, // from process.env, not the bundle
      "content-type": "application/json",
    },
    body: JSON.stringify(req.body),
  });
  res.status(r.status).send(await r.text());
});`,
      },
    ],
  },

  secret_committed: {
    title: 'Secret API key committed to your repository',
    category: 'secrets',
    defaultSeverity: 'critical',
    whatItMeans:
      'A private key ({{provider}}) is committed in your repository — found in {{file}} (commit {{commit}}). Anyone who can see the repo, and anyone who clones it, gets a full copy of this key and can use it as you: spend money, send emails, or read your data. Deleting it in a new commit is not enough — it stays readable in the git history until the key is rotated and the history is purged.',
    fixInstruction:
      'A {{provider}} secret is committed to my git repository (in {{file}}, commit {{commit}}). Rotate (regenerate) the key now since it must be treated as compromised, move it to a server-side environment variable, and remove it from the code. Then purge it from the git history — deleting it in a new commit leaves it readable in every earlier commit — using git filter-repo or BFG, and force-push the cleaned history.',
    fixSteps:
      '1) Rotate (regenerate) the {{provider}} key immediately — anyone with the repo already has it, so assume it is compromised. 2) Remove it from the code and load it from a server-only environment variable instead (never commit the new value). 3) Purge it from git history with git filter-repo or BFG — a plain deletion leaves it in every earlier commit — then force-push. 4) If the repo is or ever was public, rotate once more after cleaning, and check provider logs for unauthorized use.',
    codeExamples: [
      {
        stack: 'Purge from git history',
        language: 'bash',
        note: 'Removing the file going forward is not enough — rewrite history so old commits no longer contain the secret.',
        code: `# Option A — git filter-repo (recommended)
#   pip install git-filter-repo
git filter-repo --invert-paths --path {{file}}        # drop the leaking file from all history
# or scrub just the secret string from every blob:
git filter-repo --replace-text <(echo 'literal:THE_SECRET==>REMOVED')

# Option B — BFG Repo-Cleaner
#   https://rtyley.github.io/bfg-repo-cleaner/
bfg --delete-files {{file}}
git reflog expire --expire=now --all && git gc --prune=now --aggressive

# Then force-push the rewritten history (coordinate with collaborators):
git push --force --all`,
      },
      {
        stack: 'Keep secrets out of git',
        language: 'bash',
        note: 'Store the rotated key in an env file that is never committed.',
        code: `# .env  (local only — must be git-ignored, never committed)
PROVIDER_API_KEY="ROTATED_VALUE"

# .gitignore
.env
.env.*
!.env.example`,
      },
    ],
  },

  database_url_exposed: {
    title: 'Database connection string exposed in your code',
    category: 'secrets',
    defaultSeverity: 'critical',
    whatItMeans:
      "A full {{engine}} database connection string — including the username and password — is sitting in your site's public JavaScript ({{evidence}}). Anyone who opens your site can connect straight to your database and read, change, or delete everything in it. Database URLs must live only on the server, never in the browser.",
    fixInstruction:
      'A {{engine}} database connection string with credentials is hard-coded in my frontend. Move it to a server-side environment variable and never reference the database directly from the browser — all database access must go through server routes. After that I will rotate the database password.',
    fixSteps:
      "1) Change the database password immediately — treat it as compromised. 2) Remove the connection string from all frontend code and put it in a server-only environment variable. 3) Only connect to the database from your backend, and restrict the database's network access to your server.",
    codeExamples: [
      {
        stack: 'Environment variable',
        language: 'bash',
        note: 'The URL lives in a server-only env file that is never bundled to the browser.',
        code: `# .env  (add this file to .gitignore — never commit it)
DATABASE_URL="{{engine}}://app_user:CHANGED_PASSWORD@db.internal:5432/main"

# .gitignore
.env
.env.local`,
      },
      {
        stack: 'Server query (Node)',
        language: 'ts',
        code: `// db.ts — imported only by server code
import { Pool } from "pg";

export const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// A client component must NEVER import this file.
// Expose data through a server route instead:
//   const rows = await pool.query("select id, name from items where owner_id = $1", [userId]);`,
      },
    ],
  },

  supabase_rls_open: {
    title: 'Your Supabase database is open to the internet',
    category: 'database',
    defaultSeverity: 'critical',
    whatItMeans:
      "The \"{{table}}\" table returns data to anyone, with no login required. Row Level Security (RLS) is off or too permissive, so a stranger can download your users' records straight from the browser. This is the exact bug behind several public vibe-app breaches.",
    fixInstruction:
      'Enable Row Level Security on my Supabase table {{table}} and add policies so each user can only read and write their own rows (auth.uid() = user_id). Then audit every other table for the same problem and enable RLS everywhere.',
    fixSteps:
      'In the Supabase SQL editor run:\nALTER TABLE {{table}} ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owner_can_read" ON {{table}} FOR SELECT USING (auth.uid() = user_id);\nRepeat for every table that holds private data, and add INSERT/UPDATE/DELETE policies too.',
    codeExamples: [
      {
        stack: 'Supabase (SQL)',
        language: 'sql',
        note: 'Run in the Supabase SQL editor. Each policy scopes rows to their owner.',
        code: `-- 1) Turn RLS on (denies everything until a policy allows it)
alter table public.{{table}} enable row level security;

-- 2) Each user reads only their own rows
create policy "{{table}}_select_own"
  on public.{{table}} for select
  using (auth.uid() = user_id);

-- 3) Each user writes only their own rows
create policy "{{table}}_insert_own"
  on public.{{table}} for insert
  with check (auth.uid() = user_id);

create policy "{{table}}_update_own"
  on public.{{table}} for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "{{table}}_delete_own"
  on public.{{table}} for delete
  using (auth.uid() = user_id);`,
      },
      {
        stack: 'Find every unprotected table',
        language: 'sql',
        note: 'Lists tables that still have RLS disabled — fix each one.',
        code: `select schemaname, tablename
from pg_tables
where schemaname = 'public'
  and not rowsecurity;`,
      },
    ],
  },

  supabase_storage_public: {
    title: 'A Supabase storage bucket is fully public',
    category: 'database',
    defaultSeverity: 'high',
    whatItMeans:
      'The storage bucket "{{bucket}}" is marked public, so anyone can list and download every file in it without logging in. If it holds user uploads, invoices, ID documents or anything private, those files are exposed to the whole internet.',
    fixInstruction:
      'My Supabase storage bucket {{bucket}} is public. Make it private and serve files through signed URLs (createSignedUrl) so only authorised users can download them. Add Storage RLS policies that restrict access to the file owner.',
    fixSteps:
      'In Supabase → Storage, switch the "{{bucket}}" bucket from public to private. Replace public URLs with short-lived signed URLs (createSignedUrl), and add storage RLS policies (e.g. bucket_id + owner = auth.uid()) so users can only reach their own files.',
    codeExamples: [
      {
        stack: 'Signed URLs (JS)',
        language: 'ts',
        note: 'Generate a short-lived link instead of a permanent public URL.',
        code: `// Server-side: mint a 60-second link for an authorised user
const { data, error } = await supabase
  .storage
  .from("{{bucket}}")
  .createSignedUrl(\`\${userId}/\${fileName}\`, 60);

if (error) throw error;
return data.signedUrl;`,
      },
      {
        stack: 'Storage RLS (SQL)',
        language: 'sql',
        note: 'Restrict objects to a per-user folder named after their id.',
        code: `create policy "own_files_read"
  on storage.objects for select
  using (
    bucket_id = '{{bucket}}'
    and (storage.foldername(name))[1] = auth.uid()::text
  );

create policy "own_files_write"
  on storage.objects for insert
  with check (
    bucket_id = '{{bucket}}'
    and (storage.foldername(name))[1] = auth.uid()::text
  );`,
      },
    ],
  },

  firebase_rules_open: {
    title: 'Your Firebase database is open without a login',
    category: 'database',
    defaultSeverity: 'critical',
    whatItMeans:
      'Your Firestore / Realtime Database rules allow reads (and maybe writes) without authentication. Anyone can fetch — or change — your data directly. The default "test mode" rules are wide open and must be locked down before launch.',
    fixInstruction:
      'My Firebase security rules are open to the public. Rewrite them so only authenticated users can read their own data and nobody can read/write arbitrary documents, then help me deploy the new rules.',
    fixSteps:
      'Replace open Firestore rules with the locked-down version (see the code example), then run `firebase deploy --only firestore:rules`. Do the same for Realtime Database / Storage rules.',
    codeExamples: [
      {
        stack: 'Firestore rules',
        language: 'js',
        note: 'firestore.rules — deny by default, allow each user only their own docs.',
        code: `rules_version = "2";
service cloud.firestore {
  match /databases/{database}/documents {
    // Block everything unless a rule below allows it
    match /{document=**} {
      allow read, write: if false;
    }
    // Each user owns the docs under their uid
    match /users/{uid}/{document=**} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
  }
}`,
      },
      {
        stack: 'Realtime Database rules',
        language: 'json',
        code: `{
  "rules": {
    ".read": false,
    ".write": false,
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    }
  }
}`,
      },
    ],
  },

  auth_unprotected_route: {
    title: 'A private page loads without logging in',
    category: 'auth',
    defaultSeverity: 'high',
    whatItMeans:
      'The page "{{path}}" returned private-looking content without any login. If real user data is reachable there, anyone can open it directly. Protecting a page only by hiding the link is not protection.',
    fixInstruction:
      'The route {{path}} is accessible without authentication. Add a server-side auth guard so unauthenticated users are redirected to login, and make sure the underlying data is protected by row-level security too — not just the UI.',
    fixSteps:
      'Add a real authentication check on the server for {{path}} (middleware or route guard), not just a hidden link or a client-side redirect. Make sure the data source itself enforces access control.',
    codeExamples: [
      {
        stack: 'Next.js middleware',
        language: 'ts',
        note: 'Runs before the page renders — redirects anonymous users to login.',
        code: `// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(req: NextRequest) {
  const session = req.cookies.get("session")?.value;
  if (!session) {
    const login = new URL("/login", req.url);
    login.searchParams.set("next", req.nextUrl.pathname);
    return NextResponse.redirect(login);
  }
  return NextResponse.next();
}

export const config = { matcher: ["{{path}}", "/dashboard/:path*"] };`,
      },
      {
        stack: 'Server component check',
        language: 'ts',
        code: `// app{{path}}/page.tsx
import { redirect } from "next/navigation";
import { getSession } from "@/lib/auth";

export default async function Page() {
  const session = await getSession();
  if (!session) redirect("/login");
  // ...render private content for session.user only
}`,
      },
    ],
  },

  auth_client_only: {
    title: 'Login checks happen only in the browser',
    category: 'auth',
    defaultSeverity: 'medium',
    whatItMeans:
      'Your access checks (like "is this user an admin?") appear to run only in the JavaScript that everyone can see and edit. A user can bypass them with browser dev tools. Authorization must be enforced on the server / database, not just in the UI.',
    fixInstruction:
      'My role/permission checks run only on the client. Move all authorization to the server (e.g. database row-level security + server routes/functions) so the UI checks are just cosmetic and cannot be bypassed.',
    fixSteps:
      'Re-implement every permission decision on the server or in database policies (e.g. Supabase RLS). Keep client-side checks only for UX; never rely on them for security.',
    codeExamples: [
      {
        stack: 'Bad vs good (TS)',
        language: 'ts',
        note: 'The client check is cosmetic; the real gate must be on the server.',
        code: `// ❌ Client-only — anyone can flip isAdmin in dev tools
if (user.isAdmin) {
  await deleteEverything(); // the API trusted the button being hidden
}

// ✅ Server route enforces it, regardless of what the UI shows
export async function POST(req: Request) {
  const session = await getSession();
  if (session?.role !== "admin") {
    return new Response("Forbidden", { status: 403 });
  }
  await deleteEverything();
  return new Response("ok");
}`,
      },
    ],
  },

  bola_idor: {
    title: 'Anyone can read other users’ data by changing an id (IDOR)',
    category: 'auth',
    defaultSeverity: 'critical',
    whatItMeans:
      'Your endpoint "{{path}}" returns a {{resource}} record based only on the id in the URL — it does not check who is asking. We requested it with no login at all and got real record data back, then changed the id and got a different record. That means anyone can step through the ids and read other people\'s {{resource}} data (the classic "IDOR / broken object-level authorization" bug). This is the single most common serious flaw in vibe-coded apps. We only ever read (GET) — nothing was changed or deleted.',
    fixInstruction:
      'My endpoint {{path}} returns records by id without checking ownership, so it has an IDOR vulnerability. On every request, confirm the user is logged in AND that the requested {{resource}} actually belongs to them (e.g. WHERE owner_id = auth.uid()). If I use Supabase, enforce this with Row Level Security on the underlying table too — do not rely on the frontend.',
    fixSteps:
      'On the server, enforce object-level authorization for {{path}}: 1) require a valid session, 2) before returning the {{resource}}, verify it belongs to the requesting user (e.g. SELECT ... WHERE id = :id AND owner_id = :currentUser). Return 404/403 otherwise. If the data lives in Supabase/Postgres, also turn on Row Level Security so the database itself blocks cross-user reads. Hiding or randomising ids (UUIDs) is not a fix — the check must be server-side.',
    codeExamples: [
      {
        stack: 'Ownership check (TS)',
        language: 'ts',
        note: 'Scope the query to the current user — never trust the id alone.',
        code: `// ❌ Vulnerable: returns any record by id
const item = await db.query("select * from {{resource}} where id = $1", [id]);

// ✅ Fixed: only return it if it belongs to the caller
const session = await getSession();
if (!session) return res.status(401).end();

const item = await db.query(
  "select * from {{resource}} where id = $1 and owner_id = $2",
  [id, session.userId]
);
if (item.rows.length === 0) return res.status(404).end(); // 404, not 403 (don't leak existence)
return res.json(item.rows[0]);`,
      },
      {
        stack: 'Supabase RLS (SQL)',
        language: 'sql',
        note: 'Defence in depth: the database itself blocks cross-user reads.',
        code: `alter table public.{{resource}} enable row level security;

create policy "{{resource}}_owner_only"
  on public.{{resource}} for select
  using (auth.uid() = owner_id);`,
      },
    ],
  },

  graphql_introspection: {
    title: 'Your GraphQL API hands out its full schema',
    category: 'auth',
    defaultSeverity: 'low',
    whatItMeans:
      'Your GraphQL endpoint ({{path}}) allows introspection, which gives anyone a complete map of your data model and every query and mutation you support — including admin-only ones. Attackers use this to find exactly what to target. Introspection should be turned off in production.',
    fixInstruction:
      'Disable GraphQL introspection in production on my {{path}} endpoint, and make sure every query and mutation enforces authentication and authorization on the server — not just by hiding them.',
    fixSteps:
      'Disable introspection in your production GraphQL server (e.g. set introspection:false / NODE_ENV checks in Apollo). More importantly, enforce authentication and per-field authorization in your resolvers, since hiding the schema is not real protection.',
    codeExamples: [
      {
        stack: 'Apollo Server',
        language: 'ts',
        code: `const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== "production", // off in prod
});`,
      },
    ],
  },

  cors_misconfig: {
    title: 'Your API trusts any website (CORS misconfigured)',
    category: 'owasp',
    defaultSeverity: 'high',
    whatItMeans:
      "Your server tells browsers that any website ({{origin}}) is allowed to read its responses while sending the user's cookies. A malicious site that one of your logged-in users visits could quietly read their private data from your API. CORS should allow only origins you own.",
    fixInstruction:
      'My API reflects any Origin in Access-Control-Allow-Origin together with Allow-Credentials: true. Restrict CORS to an explicit allow-list of my own domains, and never combine a wildcard / reflected origin with credentials.',
    fixSteps:
      'Set Access-Control-Allow-Origin to an explicit list of your own domains instead of reflecting the request Origin or using "*". Only send Access-Control-Allow-Credentials: true for those trusted origins.',
    codeExamples: [
      {
        stack: 'Express (cors)',
        language: 'ts',
        note: 'Allow-list specific origins; reject everything else.',
        code: `import cors from "cors";

const allowed = new Set([
  "https://app.example.com",
  "https://example.com",
]);

app.use(cors({
  origin: (origin, cb) =>
    !origin || allowed.has(origin) ? cb(null, true) : cb(new Error("Not allowed")),
  credentials: true,
}));`,
      },
    ],
  },

  insecure_cookie: {
    title: 'A cookie is missing security flags',
    category: 'owasp',
    defaultSeverity: 'medium',
    whatItMeans:
      'A cookie ({{name}}) is set without the {{flags}} flag(s). Without HttpOnly, any script on the page (including an injected one) can steal it; without Secure it can leak over plain HTTP; without SameSite it can be abused for cross-site request forgery. Session and login cookies especially need all three.',
    fixInstruction:
      'Set my session/auth cookies (including {{name}}) with HttpOnly, Secure and SameSite=Lax (or Strict). Make sure no sensitive cookie is readable from JavaScript.',
    fixSteps:
      'When setting cookies (especially session/auth), add the attributes: HttpOnly; Secure; SameSite=Lax (or Strict). Configure this in your auth library or server framework so every sensitive cookie carries them.',
    codeExamples: [
      {
        stack: 'Node / Express',
        language: 'ts',
        code: `res.cookie("{{name}}", token, {
  httpOnly: true,   // not readable by JavaScript
  secure: true,     // HTTPS only
  sameSite: "lax",  // blocks most CSRF
  maxAge: 1000 * 60 * 60 * 24 * 7,
  path: "/",
});`,
      },
      {
        stack: 'Next.js (cookies API)',
        language: 'ts',
        code: `import { cookies } from "next/headers";

cookies().set("{{name}}", token, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
});`,
      },
    ],
  },

  weak_csp: {
    title: 'Your Content-Security-Policy is weak',
    category: 'owasp',
    defaultSeverity: 'low',
    whatItMeans:
      "You do send a Content-Security-Policy, but it contains {{weakness}}, which largely cancels out its protection — it still allows the kind of injected-script (XSS) attacks a CSP is meant to block. A CSP is only as strong as its weakest source.",
    fixInstruction:
      "Tighten my Content-Security-Policy: remove 'unsafe-inline', 'unsafe-eval' and wildcard (*) sources from script-src, and use per-response nonces or hashes for any inline scripts.",
    fixSteps:
      "Rewrite your Content-Security-Policy without 'unsafe-inline', 'unsafe-eval', or wildcard (*) sources in script-src/default-src. Use per-response nonces or content hashes for any inline scripts you genuinely need.",
    codeExamples: [
      {
        stack: 'Strong CSP header',
        language: 'text',
        note: 'A nonce-based policy — every inline <script> must carry the matching nonce.',
        code: `Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM_PER_REQUEST}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';`,
      },
    ],
  },

  mixed_content: {
    title: 'Your secure page loads insecure (HTTP) content',
    category: 'owasp',
    defaultSeverity: 'low',
    whatItMeans:
      'Your page is served over HTTPS but pulls in active resources over plain HTTP ({{example}}). Those can be read or tampered with by anyone on the network, and modern browsers will often block them — which can silently break parts of your site.',
    fixInstruction:
      'Some scripts/styles/iframes on my site load over http:// instead of https:// ({{example}}). Update every resource URL to https (or protocol-relative) so there is no mixed content.',
    fixSteps:
      'Update every http:// resource URL on your HTTPS pages to https://. Add a Content-Security-Policy directive "upgrade-insecure-requests" as a safety net, and fix the underlying links.',
  },

  missing_security_headers: {
    title: 'Missing protective HTTP headers',
    category: 'owasp',
    defaultSeverity: 'medium',
    whatItMeans:
      'Your site is missing standard security headers ({{headers}}). These help block common attacks like clickjacking and content-type tricks. Adding them is quick and low-risk.',
    fixInstruction:
      'Add the security headers {{headers}} to all responses: Content-Security-Policy, X-Frame-Options: DENY, Strict-Transport-Security, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin.',
    fixSteps:
      'Configure your host/CDN (Vercel, Netlify, Cloudflare, etc.) to send: Content-Security-Policy, X-Frame-Options: DENY, Strict-Transport-Security, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin.',
    codeExamples: [
      {
        stack: 'Next.js (next.config)',
        language: 'js',
        code: `// next.config.mjs
const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
];

export default {
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};`,
      },
      {
        stack: 'Vercel / Netlify',
        language: 'json',
        note: 'vercel.json — applies the headers at the edge for every route.',
        code: `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload" }
      ]
    }
  ]
}`,
      },
    ],
  },

  exposed_env_file: {
    title: 'Your environment file is publicly downloadable',
    category: 'owasp',
    defaultSeverity: 'critical',
    whatItMeans:
      'The file "{{path}}" is reachable on your live site. These files usually contain passwords, database URLs and API keys. Anyone can download it. It must never be served to the public.',
    fixInstruction:
      'The file {{path}} is publicly accessible on my deployed site. Make sure it is not deployed or served, add it to .gitignore and deploy-ignore, and block access to it at the host. I will rotate any secret it contained.',
    fixSteps:
      'Remove {{path}} from anything that gets deployed, block it at the host/CDN, add it to .gitignore, and rotate every secret it contained — assume they are compromised.',
    codeExamples: [
      {
        stack: 'Ignore files',
        language: 'bash',
        code: `# .gitignore  AND  .vercelignore / .dockerignore
.env
.env.*
!.env.example`,
      },
    ],
  },

  exposed_git: {
    title: 'Your .git folder is exposed',
    category: 'owasp',
    defaultSeverity: 'high',
    whatItMeans:
      'Your live site exposes the ".git" folder ({{path}}). Attackers can use it to download your entire source code and its history — including any secrets you ever committed.',
    fixInstruction:
      'My deployed site exposes the .git directory ({{path}}). Make sure .git is never deployed and block public access to /.git on the host.',
    fixSteps:
      'Ensure .git is not included in your deploy output and block /.git/* at the host/CDN. Then review git history for committed secrets and rotate them.',
    codeExamples: [
      {
        stack: 'Nginx',
        language: 'text',
        code: `location ~ /\\.git {
  deny all;
  return 404;
}`,
      },
    ],
  },

  exposed_backup: {
    title: 'A database backup or archive is downloadable',
    category: 'owasp',
    defaultSeverity: 'critical',
    whatItMeans:
      'The file "{{path}}" is publicly downloadable from your live site. Backups and archives like this (.sql, .bak, .zip, .tar.gz) usually contain your entire database or full source code — including every password and API key inside them. Anyone can grab the whole thing.',
    fixInstruction:
      'The file {{path}} is publicly downloadable on my site. Remove it from anything that gets deployed, block access to it on the host, and I will rotate every secret it might contain.',
    fixSteps:
      'Delete {{path}} from your deploy output, block backup/archive extensions (.sql, .bak, .zip, .tar.gz, .dump) at your host/CDN, and add them to .gitignore and deploy-ignore. Rotate every credential that file could contain.',
  },

  exposed_config_file: {
    title: 'A configuration file is publicly accessible',
    category: 'owasp',
    defaultSeverity: 'medium',
    whatItMeans:
      'The file "{{path}}" is reachable on your live site. Config and metadata files like this can reveal your internal structure, dependencies, build setup — and sometimes credentials — giving an attacker a head start. They should not be served to the public.',
    fixInstruction:
      'The file {{path}} is publicly served on my site. Make sure it is excluded from the deployment and blocked at the host, and check whether it contains any secrets I need to rotate.',
    fixSteps:
      'Exclude {{path}} from your deploy output and block it at your host/CDN. Review it for any secrets (tokens, passwords) and rotate anything sensitive it exposed.',
  },

  exposed_sourcemap: {
    title: 'Source maps are publicly served',
    category: 'owasp',
    defaultSeverity: 'low',
    whatItMeans:
      'Your site serves source maps (.js.map) in production. They reveal your original source code, making it easier for attackers to find logic flaws and hidden endpoints. Not urgent, but better disabled in production.',
    fixInstruction:
      'Disable source maps in my production build so .js.map files are not served publicly.',
    fixSteps:
      'Disable source map generation/serving for production builds (or restrict access to them at the host).',
    codeExamples: [
      {
        stack: 'Vite / Next.js',
        language: 'js',
        code: `// vite.config.ts
export default { build: { sourcemap: false } };

// next.config.mjs
export default { productionBrowserSourceMaps: false };`,
      },
    ],
  },

  clickjacking: {
    title: 'Your site can be embedded by attackers (clickjacking)',
    category: 'owasp',
    defaultSeverity: 'low',
    whatItMeans:
      'Nothing stops other websites from loading your site inside a hidden frame. Attackers can trick your users into clicking things they did not intend. A single header fixes it.',
    fixInstruction:
      "Add an X-Frame-Options: DENY header (or a Content-Security-Policy frame-ancestors 'none' directive) on every response so my site cannot be embedded in other sites.",
    fixSteps:
      "Add the header X-Frame-Options: DENY, or Content-Security-Policy: frame-ancestors 'none', at your host/CDN.",
    codeExamples: [
      {
        stack: 'Response header',
        language: 'text',
        code: `X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'`,
      },
    ],
  },

  sast_finding: {
    title: 'Risky code pattern found in your source',
    category: 'code',
    defaultSeverity: 'medium',
    whatItMeans:
      'An automated code-analysis tool (Semgrep) flagged a risky pattern in {{file}} (rule "{{rule}}"){{countSuffix}}. Patterns like this — for example building a database query or HTML from raw user input, or using weak/disabled security settings — are how injection, XSS and similar bugs slip in. It is worth reviewing the flagged spot even if it turns out to be a false alarm.',
    fixInstruction:
      'A static-analysis scan flagged the rule "{{rule}}" in {{file}}. Open that file, review the flagged pattern, and rewrite it the safe way — e.g. use parameterised queries instead of string-concatenated SQL, escape/encode user input before putting it in HTML, and avoid disabling built-in security features. Then re-scan to confirm it is gone.',
    fixSteps:
      '1) Open {{file}} and find the code the rule "{{rule}}" points to. 2) Understand why it is risky (the rule name usually names the weakness, e.g. sql-injection, xss, insecure-hash). 3) Apply the standard safe pattern: parameterised queries for SQL, output-encoding for HTML, a strong algorithm for crypto, validated input for paths/commands. 4) Re-run the scan to verify the finding is resolved.',
  },

  vulnerable_dependency: {
    title: 'A dependency has a known security vulnerability',
    category: 'dependencies',
    defaultSeverity: 'high',
    whatItMeans:
      'Your project depends on {{package}} version {{version}}, which has a publicly known vulnerability ({{advisory}}). Attackers actively scan for apps using vulnerable package versions, so this can be exploited even if your own code is perfect. The fix is almost always to upgrade the package.',
    fixInstruction:
      'My project uses {{package}}@{{version}}, which has a known vulnerability ({{advisory}}). Upgrade {{package}} to the latest patched version, update the lockfile, and make sure nothing breaks. If a direct upgrade is not possible because it is a transitive dependency, add an override/resolution to force the patched version.',
    fixSteps:
      '1) Upgrade {{package}} to a patched version (for npm: `npm install {{package}}@latest` or run `npm audit fix`; for Python: `pip install -U {{package}}`; for Go: `go get {{package}}@latest`). 2) Commit the updated lockfile. 3) If {{package}} is pulled in indirectly by another package, add a package-manager override/resolution to force the safe version. 4) Re-scan to confirm the advisory {{advisory}} is cleared.',
    codeExamples: [
      {
        stack: 'npm overrides (package.json)',
        language: 'json',
        note: 'Force a patched version even when a transitive dependency pins an old one.',
        code: `{
  "overrides": {
    "{{package}}": "{{version}}"
  }
}`,
      },
    ],
  },
};

/** Fill {{placeholders}} in a string from a params map. Unknown placeholders are left as-is. */
export function interpolate(template: string, params: Record<string, string> = {}): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
    const value = params[key];
    return value !== undefined ? value : `{{${key}}}`;
  });
}

/**
 * Resolve the copy-paste fix prompt for a finding on a given platform.
 * For AI builders we wrap the core instruction with the platform's prompt prefix;
 * for `generic` we return the step-by-step manual fix.
 */
export function renderFix(
  type: FindingType,
  platform: Platform,
  params: Record<string, string> = {}
): string {
  const entry = CATALOG[type];
  if (platform === 'generic') return interpolate(entry.fixSteps, params);

  const override = entry.fixOverrides?.[platform];
  const body = interpolate(override ?? entry.fixInstruction, params);
  const prefix = PLATFORM_META[platform].promptPrefix;
  return prefix ? `${prefix} "${body}"` : body;
}

/** Resolve the plain-language explanation for a finding. */
export function renderMeaning(type: FindingType, params: Record<string, string> = {}): string {
  return interpolate(CATALOG[type].whatItMeans, params);
}

/** Resolve the developed code examples for a finding (placeholders filled), or [] if none. */
export function renderCodeExamples(
  type: FindingType,
  params: Record<string, string> = {}
): CodeExample[] {
  return (CATALOG[type].codeExamples ?? []).map((ex) => ({
    ...ex,
    code: interpolate(ex.code, params),
    note: ex.note ? interpolate(ex.note, params) : ex.note,
  }));
}
