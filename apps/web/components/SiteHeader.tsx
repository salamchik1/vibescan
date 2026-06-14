import Link from 'next/link';

/**
 * Twenty-style brand mark: a black rounded square (with a hint of depth) holding
 * a white shield + checkmark — "your app, scanned & secure".
 */
function BrandMark() {
  return (
    <span
      aria-hidden
      className="flex h-9 w-9 items-center justify-center rounded-[10px] bg-gradient-to-br from-[#2b2b33] to-[#0a0a0c] shadow-[0_2px_8px_rgba(0,0,0,0.28),inset_0_1px_0_rgba(255,255,255,0.08)]"
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

/** Shared top bar used across the scanner and tools pages, styled after Twenty. */
export function SiteHeader({ active }: { active?: 'scan' | 'tools' | 'account' }) {
  const links: { href: string; label: string; key: NonNullable<typeof active> }[] = [
    { href: '/', label: 'Scanner', key: 'scan' },
    { href: '/tools', label: 'Tools', key: 'tools' },
    { href: '/dashboard', label: 'Account', key: 'account' },
  ];

  return (
    <header className="sticky top-0 z-40 -mx-5 mb-2 border-b border-ink/[0.07] bg-paper/80 px-5 backdrop-blur-md">
      <div className="flex h-16 w-full items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 font-ui text-[16px] tracking-tight text-ink">
          <BrandMark />
          <span className="leading-none">
            <span className="font-bold">Vibe</span>
            <span className="font-medium text-ink/55">Scan</span>
          </span>
        </Link>

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

        <div className="flex items-center gap-2">
          <Link
            href="/login"
            className="hidden btn-secondary !py-2 text-sm sm:inline-flex"
          >
            Log in
          </Link>
          <Link href="/login" className="btn-primary !py-2 text-sm">
            Get started
          </Link>
        </div>
      </div>
    </header>
  );
}
