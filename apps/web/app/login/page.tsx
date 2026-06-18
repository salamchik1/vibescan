import { SiteHeader } from '../../components/SiteHeader';
import { authConfigured } from '../../lib/supabase/config';
import { LoginForm } from './LoginForm';

// Friendly copy for the ?error= codes that /auth/confirm redirects back with.
const ERROR_MESSAGES: Record<string, string> = {
  not_configured: 'Login isn’t configured yet. Add your Supabase keys to enable accounts.',
  link_invalid: 'That sign-in link is invalid or has expired. Request a new one below.',
  oauth_failed: 'We couldn’t finish signing you in with that provider. Please try again.',
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  const errorMessage = error ? ERROR_MESSAGES[error] ?? ERROR_MESSAGES.oauth_failed : null;

  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col items-center px-5 py-12 sm:py-16">
      <SiteHeader />

      {errorMessage && (
        <div className="mt-12 w-full max-w-sm rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-600">
          {errorMessage}
        </div>
      )}

      <LoginForm configured={authConfigured} />
    </main>
  );
}
