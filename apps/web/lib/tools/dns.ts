// Shared types for the DNS security checker (server route ↔ client component).
import type { Check } from '../../components/tools/CheckRow';

export interface DnsResult {
  domain: string;
  /** DNSSEC validated (resolver AD flag) and a DS record exists at the parent. */
  dnssec: boolean;
  hasDs: boolean;
  /** Raw CAA records, e.g. ['0 issue "letsencrypt.org"']. */
  caa: string[];
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  summary: string;
  checks: Check[];
}
