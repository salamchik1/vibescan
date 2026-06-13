# Scanner service: Node + Playwright (Chromium preinstalled) + optional gitleaks.
# Playwright base image ships the browser and OS deps, so no extra install needed.
FROM mcr.microsoft.com/playwright:v1.49.0-jammy

WORKDIR /app

# Optional deep secret scanning. Comment out if you don't want gitleaks in the image.
# Pick the gitleaks build matching the host architecture so the image works on
# both x86 (amd64) and ARM hosts (e.g. Oracle Cloud Ampere A1 free tier).
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
# tsx is a runtime dependency (we run TS directly), so --omit=dev keeps it.
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
# Render/Railway override PORT at runtime; config.ts honors it. 8787 is the local default.
ENV SCANNER_PORT=8787
EXPOSE 8787

CMD ["npm", "run", "start", "--workspace", "@vibescan/scanner"]
