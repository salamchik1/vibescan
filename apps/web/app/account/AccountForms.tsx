'use client';

import { useActionState } from 'react';
import { updateProfile, deleteAccount, type ProfileState } from './actions';

const initial: ProfileState = { ok: false, message: '' };

export function ProfileForm({ defaultName }: { defaultName: string }) {
  const [state, formAction, pending] = useActionState(updateProfile, initial);

  return (
    <form action={formAction} className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
      <input
        type="text"
        name="full_name"
        defaultValue={defaultName}
        maxLength={80}
        placeholder="Your name"
        className="w-full rounded-lg border border-ink/15 bg-white px-4 py-2.5 text-ink shadow-card placeholder-ink/40 outline-none focus:border-ink/40 focus:ring-2 focus:ring-ink/10 sm:max-w-xs"
      />
      <button type="submit" disabled={pending} className="btn-primary !py-2.5 px-5 disabled:opacity-50">
        {pending ? 'Saving…' : 'Save'}
      </button>
      {state.message && (
        <span className={`text-sm ${state.ok ? 'text-emerald-600' : 'text-red-600'}`}>
          {state.message}
        </span>
      )}
    </form>
  );
}

export function DeleteAccountButton() {
  return (
    <form
      action={deleteAccount}
      onSubmit={(e) => {
        if (
          !window.confirm(
            'Delete your account permanently? This removes your scan history and cannot be undone.'
          )
        ) {
          e.preventDefault();
        }
      }}
    >
      <button
        type="submit"
        className="rounded-lg border border-red-500/40 px-4 py-2 text-sm font-medium text-red-600 transition hover:bg-red-500/10"
      >
        Delete account
      </button>
    </form>
  );
}
