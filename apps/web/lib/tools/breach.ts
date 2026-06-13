// Shared types for the data breach checker (server route ↔ client component).

export interface Breach {
  name: string;
  domain: string;
  breachDate: string;
  pwnCount: number;
  description: string;
  dataClasses: string[];
  isVerified: boolean;
  isSensitive: boolean;
}

export interface BreachResult {
  email: string;
  /** True when the address was found in one or more breaches. */
  pwned: boolean;
  breachCount: number;
  breaches: Breach[];
}
