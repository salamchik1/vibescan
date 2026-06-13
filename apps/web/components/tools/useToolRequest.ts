'use client';

import { useCallback, useState } from 'react';

interface State<T> {
  loading: boolean;
  error: string | null;
  data: T | null;
}

/**
 * Shared client helper for the network tools: POSTs a JSON body to a tool API
 * route and tracks loading / error / data. Server routes return `{ error }` on
 * failure and the result shape `T` on success.
 */
export function useToolRequest<T>(endpoint: string) {
  const [state, setState] = useState<State<T>>({ loading: false, error: null, data: null });

  const run = useCallback(
    async (body: Record<string, unknown>) => {
      setState({ loading: true, error: null, data: null });
      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        });
        const json = await res.json().catch(() => ({}));
        if (!res.ok) {
          setState({ loading: false, error: json?.error ?? 'Something went wrong.', data: null });
          return;
        }
        setState({ loading: false, error: null, data: json as T });
      } catch {
        setState({ loading: false, error: 'Network error — please try again.', data: null });
      }
    },
    [endpoint]
  );

  return { ...state, run };
}
