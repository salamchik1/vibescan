'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { createClient } from '../lib/supabase/client';
import { authConfigured } from '../lib/supabase/config';

/**
 * Twenty-style brand mark: a black rounded square (with a hint of depth) holding
 * a white shield + checkmark — "your app, scanned & secure".
 */
function BrandMark() {
  return (
    <span
      aria-hidden
      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[10px] bg-gradient-to-br from-[#2b2b33] to-[#0a0a0c] shadow-[0_2px_8px_rgba(0,0,0,0.28),inset_0_1px_0_rgba(255,255,255,0.08)]"
    >
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path
          d="M12 2.6 L19.2 5.3 C19.4 5.4 19.5 5.6 19.5 5.8 V11.3 C19.5 16.2 16.4 19.8 12.3 21.3 C12.1 21.4 11.9 21.4 11.7 21.3 C7.6 19.8 4.5 16.2 4.5 11.3 V5.8 C4.5 5.6 4.6 5.4 4.8 5.3 Z"
          fill="white"
        />
        <path
          d="M8.7 11.9 L11 14.2 L15.4 9.2"
          stroke="#0B0B0E"
          strokeWidth="2.1"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </span>
  );
}

type ActiveKey = 'scan' | 'tools' | 'account';

/** Initials avatar built from the user's name/email — no external <img>, so the CSP stays tight. */
function Avatar({ label }: { label: string }) {
  const initial = label.trim().charAt(0).toUpperCase() || '?';
  return (
    <span
      aria-hidden
      className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-ink text-xs font-semibold text-paper"
    >
      {initial}
    </span>
  );
}

/**
 * Reads the current session in the browser via the public Supabase client and
 * stays in sync through onAuthStateChange. Returns `undefined` while loading
 * (so we render the neutral logged-out CTAs and never flash the wrong state).
 */
function useSessionEmail(): string | null | undefined {
  const [email, setEmail] = useState<string | null | undefined>(
    authConfigured ? undefined : null
  );

  useEffect(() => {
    if (!authConfigured) return;
    const supabase = createClient();
    let active = true;

    supabase.auth.getUser().then(({ data }) => {
      if (active) setEmail(data.user?.email ?? null);
    });

    const { data: sub } = supabase.auth.onAuthStateChange((_event, session) => {
      setEmail(session?.user?.email ?? null);
    });

    return () => {
      active = false;
      sub.subscription.unsubscribe();
    };
  }, []);

  return email;
}

/** Shared top bar used across the scanner and tools pages, styled after Twenty. */
export function SiteHeader({ active }: { active?: ActiveKey }) {
  const [open, setOpen] = useState(false);
  const email = useSessionEmail();
  const signedIn = Boolean(email);

  const links: { href: string; label: string; key: ActiveKey }[] = [
    { href: '/', label: 'Scanner', key: 'scan' },
    { href: '/tools', label: 'Tools', key: 'tools' },
  ];

  return (
    <header className="sticky top-0 z-40 -mx-5 mb-2 border-b border-ink/[0.07] bg-paper/80 px-5 backdrop-blur-md">
      <div className="flex h-16 w-full items-center justify-between gap-3">
        <Link
          href="/"
          className="flex min-w-0 items-center gap-2.5 font-ui text-[16px] tracking-tight text-ink"
        >
          <BrandMark />
          <span className="truncate leading-none">
            <span className="font-bold">Vibe</span>
            <span className="font-medium text-ink/55">Scan</span>
          </span>
        </Link>

        {/* Desktop nav */}
        <nav className="hidden items-center gap-1 text-sm sm:flex">
          {links.map((l, i) => (
            <span key={l.key} className="flex items-center">
              {i > 0 && <span aria-hidden className="mx-1 h-4 w-px bg-ink/10" />}
              <Link
                href={l.href}
                className={`rounded-md px-3 py-1.5 transition ${
                  active === l.key ? 'text-ink' : 'text-ink/60 hover:text-ink'
                }`}
              >
                {l.label}
              </Link>
            </span>
          ))}
          {signedIn && (
            <span className="flex items-center">
              <span aria-hidden className="mx-1 h-4 w-px bg-ink/10" />
              <Link
                href="/dashboard"
                className={`rounded-md px-3 py-1.5 transition ${
                  active === 'account' ? 'text-ink' : 'text-ink/60 hover:text-ink'
                }`}
              >
                Scans
              </Link>
            </span>
          )}
        </nav>

        {/* Desktop CTAs */}
        <div className="hidden items-center gap-2 sm:flex">
          {signedIn ? (
            <>
              <Link
                href="/account"
                title={email ?? 'Account'}
                className="flex items-center gap-2 rounded-full border border-ink/15 py-1 pl-1 pr-3 text-sm text-ink/70 transition hover:border-ink/40 hover:text-ink"
              >
                <Avatar label={email ?? '?'} />
                <span className="max-w-[12rem] truncate">{email}</span>
              </Link>
              <form action="/auth/signout" method="post">
                <button className="btn-secondary !py-2 text-sm">Sign out</button>
              </form>
            </>
          ) : (
            <>
              <Link href="/login" className="btn-secondary !py-2 text-sm">
                Log in
              </Link>
              <Link href="/login" className="btn-primary !py-2 text-sm">
                Get started
              </Link>
            </>
          )}
        </div>

        {/* Mobile menu toggle */}
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-label={open ? 'Close menu' : 'Open menu'}
          aria-expanded={open}
          className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-ink/10 bg-card text-ink shadow-card sm:hidden"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden>
            {open ? (
              <path
                d="M6 6l12 12M18 6L6 18"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
            ) : (
              <path
                d="M4 7h16M4 12h16M4 17h16"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
            )}
          </svg>
        </button>
      </div>

      {/* Mobile dropdown */}
      {open && (
        <nav className="border-t border-ink/[0.07] py-3 sm:hidden">
          <div className="flex flex-col gap-1 text-sm">
            {links.map((l) => (
              <Link
                key={l.key}
                href={l.href}
                onClick={() => setOpen(false)}
                className={`rounded-lg px-3 py-2.5 transition ${
                  active === l.key ? 'bg-ink/[0.05] font-medium text-ink' : 'text-ink/70 hover:bg-ink/[0.04]'
                }`}
              >
                {l.label}
              </Link>
            ))}
            {signedIn && (
              <>
                <Link
                  href="/dashboard"
                  onClick={() => setOpen(false)}
                  className="rounded-lg px-3 py-2.5 text-ink/70 transition hover:bg-ink/[0.04]"
                >
                  Scans
                </Link>
                <Link
                  href="/account"
                  onClick={() => setOpen(false)}
                  className={`rounded-lg px-3 py-2.5 transition ${
                    active === 'account'
                      ? 'bg-ink/[0.05] font-medium text-ink'
                      : 'text-ink/70 hover:bg-ink/[0.04]'
                  }`}
                >
                  Account
                </Link>
              </>
            )}
          </div>
          <div className="mt-3 flex flex-col gap-2">
            {signedIn ? (
              <form action="/auth/signout" method="post">
                <button className="btn-secondary w-full !py-2.5 text-sm">Sign out</button>
              </form>
            ) : (
              <>
                <Link
                  href="/login"
                  onClick={() => setOpen(false)}
                  className="btn-secondary w-full !py-2.5 text-sm"
                >
                  Log in
                </Link>
                <Link
                  href="/login"
                  onClick={() => setOpen(false)}
                  className="btn-primary w-full !py-2.5 text-sm"
                >
                  Get started
                </Link>
              </>
            )}
          </div>
        </nav>
      )}
    </header>
  );
}
