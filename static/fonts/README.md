# Self-hosted fonts

Both families are licensed under the SIL Open Font License 1.1 and are served
from this site, not from a third-party CDN. No request leaves the origin at
runtime, so there is no `fonts.googleapis.com` / `fonts.gstatic.com` dependency
and nothing to leak about visitors.

| File | Family | Subset | Axis |
|---|---|---|---|
| `inter-latin.woff2` | Inter | latin | variable `wght 100..900` |
| `inter-latin-ext.woff2` | Inter | latin-ext | variable `wght 100..900` |
| `jetbrains-mono-latin.woff2` | JetBrains Mono | latin | variable `wght 400..700` |
| `jetbrains-mono-latin-ext.woff2` | JetBrains Mono | latin-ext | variable `wght 400..700` |

Both are **variable** fonts, so one file covers every weight in its range.

Sourced from the Google Fonts CSS API (Inter `v20`, JetBrains Mono `v24`):

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
curl -H "User-Agent: $UA" "https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap"
curl -H "User-Agent: $UA" "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400..700&display=swap"
```

A modern User-Agent is required — the API serves older `ttf`/`woff` formats to
UAs it does not recognise. Take the `src:` URL from the block whose
`unicode-range` starts `U+0000-00FF` (latin) and `U+0100-02BA` (latin-ext).

The `@font-face` declarations, the `--rs-font-sans` / `--rs-font-mono` custom
properties, and the `unicode-range` values live in `assets/css/custom.css`.

These live in `static/` rather than `assets/` on purpose. Hugo copies `static/`
verbatim, so the files are guaranteed to exist at `/fonts/*.woff2` and can be
referenced by absolute path from plain CSS. Under `assets/` they would only be
published if some template called `.RelPermalink` on each one, which would mean
turning `custom.css` into a Hugo template just to emit the URLs. Fingerprinting
buys little here: the filenames already encode the upstream version, and the
files change only when deliberately updated.

The Inter latin subset is preloaded in `layouts/_partials/custom/head.html`.

To update, re-run the commands above and replace the files. Keep the filenames
so the CSS and the preload tag do not need editing.

Upstream: <https://github.com/rsms/inter> · <https://github.com/JetBrains/JetBrainsMono>
