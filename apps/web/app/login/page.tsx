'use client';

import { useActionState } from 'react';
import { SiteHeader } from '../../components/SiteHeader';
import { sendMagicLink, type LoginState } from './actions';

const initial: LoginState = { ok: false, message: '' };

export default function LoginPage() {
  const [state, formAction, pending] = useActionState(sendMagicLink, initial);

  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col items-center px-5 py-12 sm:py-16">
      <SiteHeader />

      <section className="mt-16 w-full max-w-sm">
        <h1 className="text-2xl font-bold text-ink">Sign in to VibeScan</h1>
        <p className="mt-2 text-sm text-ink/60">
          No password. Enter your email and we’ll send you a one-click sign-in link so your scan
          history and reports stay in one place.
        </p>

        {state.ok ? (
          <div className="mt-8 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-4 text-sm text-emerald-200">
            {state.message}
          </div>
        ) : (
          <form action={formAction} className="mt-8 flex flex-col gap-3">
            <input
              type="email"
              name="email"
              required
              autoComplete="email"
              placeholder="you@example.com"
              className="w-full rounded-lg border border-ink/15 bg-white px-4 py-3 text-ink shadow-card placeholder-ink/40 outline-none focus:border-ink/40 focus:ring-2 focus:ring-ink/10"
            />
            <button
              type="submit"
              disabled={pending}
              className="btn-primary w-full px-5 py-3 disabled:opacity-50"
            >
              {pending ? 'Sending…' : 'Send me a sign-in link'}
            </button>
            {state.message && !state.ok && (
              <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-600">
                {state.message}
              </p>
            )}
          </form>
        )}
      </section>
    </main>
  );
}
