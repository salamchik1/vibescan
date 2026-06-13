# ZeeFrames homepage — static mirror

A fully offline, pixel-faithful mirror of the **zeeframes.com** homepage
(downloaded 2026-06-12). All HTML, CSS, JS, images, fonts, and the process
video are stored locally; every `zeeframes.com` asset URL was rewritten to a
relative local path, so it renders with **no network access**.

## Run it

```bash
node serve.mjs          # serves on http://localhost:8080
# or pick a port:
PORT=3001 node serve.mjs
```

Then open <http://localhost:8080>.

> Opening `index.html` directly via `file://` mostly works, but some browsers
> block `fetch`/font loading over `file://`. Using `serve.mjs` avoids that.

## What's included / what's not

- ✅ Full homepage markup, all CSS (`frontend-assets/css/*`), JS, SVG icons,
  WebP images, Google Fonts (Geologica + Inter, stored under `_ext/`), and the
  28 MB process video (`frontend-assets/media/zeeframes-process.mp4`).
- 🔗 **Navigation links** (About, Services, Work, Insights, etc.) still point to
  the live site — this is a *homepage-only* mirror by design.
- ⚠️ Backend-dependent widgets (contact form, chatbot stream, email capture)
  POST to `zeeframes.com` endpoints and will fail offline — visual only.
- ℹ️ One JSON-LD `logo` field references `https://zeeframes.com/assets/images/svgs/logo.svg`,
  which 404s on the original site too. Left as-is for fidelity (invisible SEO metadata).

## How it was built

`mirror.mjs` fetches the homepage, discovers every same-origin/font asset
(including nested `url()` refs inside CSS), downloads them preserving directory
structure, and rewrites all absolute URLs to local relative paths. Re-run with
`node mirror.mjs` to refresh.
