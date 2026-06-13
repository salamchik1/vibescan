export const metadata = { title: 'Terms — VibeScan' };

export default function Terms() {
  return (
    <main className="mx-auto max-w-2xl px-5 py-16 text-white/70">
      <a href="/" className="text-sm text-primary hover:text-primary-dark">
        ← Back
      </a>
      <h1 className="mt-6 text-2xl font-bold text-white">Terms of Use</h1>
      <div className="mt-4 space-y-4 text-sm leading-relaxed">
        <p>
          VibeScan performs a lightweight, read-only security check of a public web address that you
          provide. By starting a scan you confirm that you own the target site or have explicit
          permission to scan it. Scanning systems you do not control may be illegal.
        </p>
        <p>
          The scan inspects publicly available content and sends a small number of read-only requests
          to the target. It is not a penetration test and does not attempt to modify, delete, or
          exfiltrate data. No tool finds every issue — a clean result does not guarantee security.
        </p>
        <p>
          The service is provided &quot;as is&quot;, without warranty. You are responsible for how you
          use the results. We may rate-limit or block abuse.
        </p>
      </div>
    </main>
  );
}
