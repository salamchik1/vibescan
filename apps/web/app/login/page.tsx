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
        <h1 className="text-2xl font-bold text-white">Sign in to VibeScan</h1>
        <p className="mt-2 text-sm text-white/60">
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
              className="w-full rounded-xl border border-white/15 bg-white/5 px-4 py-3 text-white placeholder-white/30 outline-none focus:border-primary"
            />
            <button
              type="submit"
              disabled={pending}
              className="rounded-xl bg-primary px-5 py-3 font-ui font-semibold text-black transition hover:bg-primary-dark disabled:opacity-50"
            >
              {pending ? 'Sending…' : 'Send me a sign-in link'}
            </button>
            {state.message && !state.ok && (
              <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
                {state.message}
              </p>
            )}
          </form>
        )}
      </section>
    </main>
  );
}
