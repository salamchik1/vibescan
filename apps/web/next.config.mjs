import { config as loadEnv } from 'dotenv';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// Load the repo-root .env so a single file configures both web and scanner.
const here = dirname(fileURLToPath(import.meta.url));
loadEnv({ path: resolve(here, '../../.env') });

/** @type {import('next').NextConfig} */
const nextConfig = {
  // The shared findings package ships TypeScript source; Next must transpile it.
  transpilePackages: ['@vibescan/findings'],
};

export default nextConfig;
