-- VibeScan persistence schema.
-- Run this once in the Supabase SQL editor (Dashboard → SQL → New query → paste → Run).
-- Safe to re-run: every statement is idempotent.

-- ---------------------------------------------------------------------------
-- scans: one row per finished scan. Stores the full ScanResult as JSON so the
-- /r/{id} report page can re-render it exactly, plus a few flat columns we
-- index on for the dashboard / future monitoring & billing.
-- ---------------------------------------------------------------------------
create table if not exists public.scans (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  -- null = anonymous scan (no login). Set once the user is signed in.
  user_id     uuid references auth.users (id) on delete set null,
  -- The URL scanned, or 'Pasted code' for code scans. Shown in history.
  target      text not null,
  mode        text not null default 'url',           -- 'url' | 'code'
  score       int  not null default 0,               -- 0..100
  verdict     text not null default 'green',          -- 'red' | 'yellow' | 'green'
  -- Severity tallies, e.g. {"critical":1,"high":0,...}. Handy for list views.
  counts      jsonb not null default '{}'::jsonb,
  -- The complete ScanResult object — source of truth for rendering the report.
  result      jsonb not null
);

create index if not exists scans_user_id_created_at_idx
  on public.scans (user_id, created_at desc);

-- ---------------------------------------------------------------------------
-- Row Level Security.
-- Inserts and public-by-link reads (/r/{id}) go through the service-role key,
-- which bypasses RLS. The only thing end-user sessions need is to list their
-- OWN scans for the dashboard — so that's the single policy we expose.
-- ---------------------------------------------------------------------------
alter table public.scans enable row level security;

drop policy if exists "owners read own scans" on public.scans;
create policy "owners read own scans"
  on public.scans for select
  to authenticated
  using (auth.uid() = user_id);

-- Let a signed-in user claim/attach scans to themselves if you wire that up
-- later (e.g. associating an anonymous scan after login). Optional today.
drop policy if exists "owners update own scans" on public.scans;
create policy "owners update own scans"
  on public.scans for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- ---------------------------------------------------------------------------
-- scanner_endpoint: a single row (id = 1) that the local scanner agent keeps
-- up to date with its current public tunnel URL and a heartbeat timestamp.
-- The Next.js /api/scan route reads this at request time, so a changing
-- tunnelmole URL is picked up live — no env edit / redeploy needed. A stale
-- updated_at means the home PC is off, and the site shows "scanner offline".
-- Only the service-role key (local agent + server route) touches this table;
-- RLS is on with no public policies, so end-user sessions can't read/write it.
-- ---------------------------------------------------------------------------
create table if not exists public.scanner_endpoint (
  id          int  primary key default 1,
  url         text not null,
  updated_at  timestamptz not null default now(),
  constraint scanner_endpoint_singleton check (id = 1)
);

alter table public.scanner_endpoint enable row level security;
