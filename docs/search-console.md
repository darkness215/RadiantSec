# Search Console Setup

Repo documentation — not published to the site (`docs/` at the repo root is
outside `content/`, so Hugo never sees it).

Site: `https://radiantsec.io` · hosted on **GitHub Pages**.

## 1. Verify ownership in Google Search Console

<https://search.google.com/search-console>

Two methods work on GitHub Pages. **DNS is preferable** — it verifies the whole
domain including subdomains and survives any hosting change.

**DNS (recommended).** Add the `TXT` record Google gives you to the DNS zone for
`radiantsec.io` at your registrar. Choose the "Domain" property type, not "URL
prefix". Propagation is usually minutes.

**HTML file (fallback).** Drop Google's `google*.html` verification file into
`static/` — Hugo copies `static/` verbatim to the site root, so it lands at
`https://radiantsec.io/google*.html` after the next deploy. Keep the file
committed; removing it un-verifies the property.

## 2. Submit the sitemap

Sitemaps → add `https://radiantsec.io/sitemap.xml`.

It lists **~51 URLs**, not ~180. Tag pages are deliberately `noindex` and are
excluded — see the noindex policy in the root `CLAUDE.md`. `robots.txt` also
advertises the sitemap, but explicit submission speeds up first indexing.

## 3. Also set up Bing Webmaster Tools

<https://www.bing.com/webmasters>

Easy to dismiss given Bing's search share, but **ChatGPT search and Microsoft
Copilot are built on Bing's index**. If being cited by AI assistants matters,
this is the entry point. Bing can import the property directly from Search
Console rather than re-verifying.

## 4. What to actually check

Data takes a few days to appear, and weeks to become meaningful.

**Performance — the main report.** Filter to **average position 5–20**. Those
are queries where Google already ranks the site but hasn't committed. Improving
an existing page for one of them is far cheaper than targeting a new keyword.
Sort by impressions to find the ones worth the effort.

**Indexing → Pages.** Watch for:
- *Crawled — currently not indexed*: Google saw it and declined. Usually a
  content-quality or duplication signal.
- *Discovered — currently not indexed*: crawl budget. Should improve now that
  ~128 thin tag pages no longer compete for it.
- *Excluded by 'noindex' tag*: **expected** for tag pages. Not a problem.

**Expect the indexed-page count to fall** after the noindex change lands. That
is the intended outcome, not a regression — the ~38 real articles are what
should be indexed.

**Core Web Vitals** and **Mobile Usability** only populate with enough traffic.

## 5. Deployment caveat

The repo has no `.github/workflows/` and `public/` is git-ignored, so the build
that produces the live site happens outside this repository. Whatever runs it
needs **Hugo extended** (the OG social-card generation uses `images.Text`, which
is extended-only) and access to `assets/fonts/Inter-Variable.ttf`. If the site
is built locally and the output pushed, nothing extra is required.
