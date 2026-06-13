import Link from 'next/link';

/** Shared top bar used on the scanner and the tools pages. */
export function SiteHeader({ active }: { active?: 'scan' | 'tools' }) {
  return (
    <header className="flex w-full items-center justify-between">
      <Link href="/" className="flex items-center gap-2 font-ui font-semibold text-white">
        <span className="text-xl">🛡️</span> VibeScan
      </Link>
      <nav className="flex items-center gap-1 text-sm">
        <Link
          href="/"
          className={`rounded-full px-3 py-1 transition ${
            active === 'scan' ? 'bg-white/10 text-white' : 'text-white/60 hover:text-white'
          }`}
        >
          Scanner
        </Link>
        <Link
          href="/tools"
          className={`rounded-full px-3 py-1 transition ${
            active === 'tools' ? 'bg-white/10 text-white' : 'text-white/60 hover:text-white'
          }`}
        >
          Tools
        </Link>
      </nav>
    </header>
  );
}
