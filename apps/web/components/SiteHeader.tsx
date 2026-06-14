'use client';

import { useState } from 'react';
import Link from 'next/link';

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

/** Shared top bar used across the scanner and tools pages, styled after Twenty. */
export function SiteHeader({ active }: { active?: ActiveKey }) {
  const [open, setOpen] = useState(false);
  const links: { href: string; label: string; key: ActiveKey }[] = [
    { href: '/', label: 'Scanner', key: 'scan' },
    { href: '/tools', label: 'Tools', key: 'tools' },
    { href: '/dashboard', label: 'Account', key: 'account' },
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
        </nav>

        {/* Desktop CTAs */}
        <div className="hidden items-center gap-2 sm:flex">
          <Link href="/login" className="btn-secondary !py-2 text-sm">
            Log in
          </Link>
          <Link href="/login" className="btn-primary !py-2 text-sm">
            Get started
          </Link>
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
          </div>
          <div className="mt-3 flex flex-col gap-2">
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
          </div>
        </nav>
      )}
    </header>
  );
}
