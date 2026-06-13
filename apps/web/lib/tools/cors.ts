// Shared types for the CORS tester (server route ↔ client component).
import type { Check } from '../../components/tools/CheckRow';

export type Verdict = 'vulnerable' | 'risky' | 'permissive' | 'restricted';

export interface CorsResult {
  url: string;
  /** HTTP status of the probe request. */
  httpStatus: number;
  /** The forged Origin we sent. */
  probeOrigin: string;
  headers: {
    allowOrigin: string | null;
    allowCredentials: boolean;
    allowMethods: string | null;
    allowHeaders: string | null;
  };
  /** Whether the server reflected our arbitrary Origin back. */
  reflectsArbitrary: boolean;
  /** Whether the server echoed `Origin: null` as allowed. */
  allowsNull: boolean;
  verdict: Verdict;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  summary: string;
  checks: Check[];
}
