# Root Dockerfile for Hugging Face Spaces (Docker SDK).
# HF only builds a Dockerfile at the repo root, so this mirrors
# apps/scanner/Dockerfile (the canonical one used by Render/docker-compose).
# Build context is the repo root; it COPYs the scanner workspace from there.
# Keep the two in sync if you change build steps.
FROM mcr.microsoft.com/playwright:v1.49.0-jammy

WORKDIR /app

# Optional deep secret scanning. Pick the gitleaks build matching the host arch.
ARG GITLEAKS_VERSION=8.21.2
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
  && case "$(dpkg --print-architecture)" in \
       amd64) GL_ARCH=x64 ;; \
       arm64) GL_ARCH=arm64 ;; \
       *) GL_ARCH=x64 ;; \
     esac \
  && curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
     | tar -xz -C /usr/local/bin gitleaks \
  && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Browsers are baked into the base image; don't re-download during npm install.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# Install workspace deps. Copy manifests first for better layer caching.
COPY package.json package-lock.json* ./
COPY packages/findings/package.json packages/findings/package.json
COPY apps/scanner/package.json apps/scanner/package.json
RUN npm install --omit=dev --no-audit --no-fund --workspace @vibescan/scanner --include-workspace-root \
  || npm install --no-audit --no-fund

# Copy source.
COPY tsconfig.base.json ./
COPY packages/findings packages/findings
COPY apps/scanner apps/scanner

ENV NODE_ENV=production
# Hugging Face routes the Space's public URL to this port (see app_port in README).
ENV SCANNER_PORT=8787
EXPOSE 8787

CMD ["npm", "run", "start", "--workspace", "@vibescan/scanner"]
