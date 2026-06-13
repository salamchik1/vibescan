export const metadata = { title: 'Privacy — VibeScan' };

export default function Privacy() {
  return (
    <main className="mx-auto max-w-2xl px-5 py-16 text-white/70">
      <a href="/" className="text-sm text-primary hover:text-primary-dark">
        ← Back
      </a>
      <h1 className="mt-6 text-2xl font-bold text-white">Privacy</h1>
      <div className="mt-4 space-y-4 text-sm leading-relaxed">
        <p>
          The free scanner does not require an account. We do not ask for access to your source code
          or repositories.
        </p>
        <p>
          When a secret is detected, we only ever store and display a <em>masked</em> version (for
          example <code>sk_live_****abcd</code>) — never the full value. The page content downloaded
          during a scan is discarded as soon as the scan finishes; it is not stored.
        </p>
        <p>
          To tell a live key from one that was already revoked, we may make a single{' '}
          <strong>read-only</strong> request with the detected key to the service that issued it
          (for example, asking Stripe for your account balance or GitHub &ldquo;who am I&rdquo;). We
          never use the key to read, change, send, or delete anything, the request is sent only to
          that provider&rsquo;s official endpoint, and the raw key is never written to our logs or
          storage — only the result (live / revoked) is kept with the report.
        </p>
        <p>
          We may keep minimal, non-identifying metrics (for example, that a scan happened) to operate
          and improve the service.
        </p>
      </div>
    </main>
  );
}
