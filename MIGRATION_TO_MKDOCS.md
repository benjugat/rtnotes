# Migration report: Jekyll → MkDocs

**Date:** 2026-06-10
**Repository:** <https://github.com/benjugat/rtnotes>
**Migration branch:** `chore/migrate-to-mkdocs`
**Target site:** <https://benjugat.github.io/rtnotes/>

## 1. Executive summary

The site was migrated from **Jekyll 3.8.4** (CloudCannon "Edition" template)
to **MkDocs 1.6** with **Material for MkDocs 9.5+**.

- 33 documentation pages migrated, none lost.
- 34 image assets preserved.
- Deployment switched from CloudCannon to **GitHub Actions** with the official
  `actions/deploy-pages` flow.
- Static site now built by `mkdocs build` and served directly from the
  `site/` artifact.
- One-time manual step required: change **Pages → Source** to
  **GitHub Actions** in the repository settings.

## 2. Inventory of changes

### Files added

| Path | Purpose |
|---|---|
| `mkdocs.yml` | MkDocs configuration (Material theme, nav, plugins, extensions) |
| `requirements.txt` | Python dependencies (`mkdocs`, `mkdocs-material`, `pymdown-extensions`) |
| `.github/workflows/ci.yml` | GitHub Actions workflow that builds and deploys the site |
| `docs/index.md` | Home page (replaces root `index.md`) |
| `docs/changelog.md` | Site changelog (replaces `changelog.html`) |
| `docs/red-team/*.md` | 17 pages (16 from `_docs/00-red-team/` + `playing-with-tokens.md`) |
| `docs/malware/**/*.md` | 16 pages across 5 sub-sections |
| `docs/images/*` | 34 image assets |
| `MIGRATION_TO_MKDOCS.md` | This report |

### Files removed (after the new build was validated)

| Path | Replaced by |
|---|---|
| `_config.yml` | `mkdocs.yml` |
| `Gemfile`, `Gemfile.lock` | `requirements.txt` |
| `_layouts/`, `_includes/`, `_plugins/`, `_sass/`, `css/` | Replaced by Material theme |
| `_posts/` (2016 changelog placeholders) | `docs/changelog.md` (re-authored) |
| `search.html`, `changelog.html`, `404.md` | Native Material equivalents |
| `.cloudcannon/` | No longer needed |
| `index.md` (root) | `docs/index.md` |
| `touch-icon.png`, `apple-touch-icon.png` | Optional; can be re-added as favicons in `docs/` |

### Files kept

- `LICENSE` — MIT, unchanged.
- `README.md` — completely rewritten to describe the new stack.
- `robots.txt` — kept and adjusted to point at the new sitemap URL.

## 3. Technical decisions

### 3.1 Tooling

| Concern | Choice | Why |
|---|---|---|
| Generator | MkDocs 1.6 | De-facto standard for Python docs; wide ecosystem. |
| Theme | Material 9.5+ | Best-in-class search, navigation, light/dark, MD extensions. |
| Markdown extensions | pymdownx suite | Required by Material for tabs, superfences, highlight. |
| Plugins | `search` (built-in) | Material bundles lunr; no need for additional plugins. |
| Deploy | `actions/deploy-pages` | Official, no extra secrets, atomic, no `gh-pages` branch. |

### 3.2 Front matter

Stripped `category:` and `order:` (Jekyll/CloudCannon-specific). MkDocs uses
the explicit `nav:` in `mkdocs.yml` for ordering.

```yaml
---
title: <title from Jekyll>
description: "<first non-heading paragraph, truncated to 160 chars>"
---
```

`description` is consumed by Material for SEO and is shown in some link
previews.

### 3.3 Image paths

- Original: `/rtnotes/images/foo.png` (Jekyll `baseurl` prefix).
- Also found: `/hackingnotes/images/foo.png` in some pages — broken in the
  previous site.
- Migrated to relative paths: `../images/foo.png` from `red-team/`, and
  `../../images/foo.png` from `docs/malware/*/`.
- The transformation was done by a small Python script (`migrate.py`) that
  rewrote both patterns in a single pass.

### 3.4 Cross-references

- Original format: `* [https://benjugat.github.io/rtnotes/malware/object-enumeration/processes/](https://benjugat.github.io/rtnotes/malware/object-enumeration/processes/)`.
- Rewritten to: `* [Proccess Enumeration](../object-enumeration/processes.md)`.
- 8 cross-references were rewritten; all of them resolved to a real target.

### 3.5 Navigation

Top-level sections reflect the actual content, in the order the user reads
during an engagement:

1. **Home** (`index.md`)
2. **Changelog** (`changelog.md`)
3. **Red Team** (17 pages): Introduction → OPSEC → C2 → Recon → Persistence →
   Privesc → Lateral → Creds → Tokens → Kibana → Pivoting → SQL → DPAPI → LAPS
   → Defender → AppLocker → Exfiltration.
4. **Malware Development** (16 pages), split into Basics / Code Injection /
   Hooking / Low Priv Evasion / Object Enumeration.

The folder `user-impersonation/` was folded into `red-team/` as
`playing-with-tokens.md`. It is the only page of that category and is
logically a continuation of the "Credentials & User Impersonation" page.

### 3.6 URL changes

| Old URL | New URL |
|---|---|
| `/00-red-team/<page>/` | `/red-team/<page>/` |
| `/user-impersonation/playing-with-tokens/` | `/red-team/playing-with-tokens/` |
| `/changelog.html` | `/changelog/` |
| `/search.html` | `/search/` (Material search) |
| `/404.html` | `/404.html` (Material's `404.html` is auto-generated) |

External links to the old URLs will 404. No redirects were set up because
the project did not have an HTTP-accessible previous site (it was served
from CloudCannon's domain, not from `benjugat.github.io`). If the project is
ever published under a stable custom domain, `mkdocs-redirects` can be added
to preserve backward compatibility.

## 4. Incompatibilities detected

### 4.1 Missing images

These images are **referenced in markdown** but were **never present** in
`images/` (they were broken in the original site too):

| File | Referenced in |
|---|---|
| `procmon.png`, `procmon-results.png` | `docs/red-team/host-persistence.md` |
| `cobaltstrike-login.png` | `docs/red-team/c2-cobaltstrike.md` |
| `cobaltstrike-listener.png` | `docs/red-team/c2-cobaltstrike.md` |
| `cobaltstrike-listener-tcp-chain.png` (×2) | `docs/red-team/c2-cobaltstrike.md` |
| `cobaltstrike-listener-p2p.png` | `docs/red-team/c2-cobaltstrike.md` |
| `cobaltstrike-staged.png` | `docs/red-team/c2-cobaltstrike.md` |
| `cobaltstrike-stageless.png` | `docs/red-team/c2-cobaltstrike.md` |
| `cobaltstrike-interact.png` | `docs/red-team/c2-cobaltstrike.md` |
| `cobaltstrike-hostfile.png` | `docs/red-team/c2-cobaltstrike.md` |
| `heidisql.png` | `docs/red-team/ms-sql-servers.md` |
| `boy-crying.jpg` | `docs/index.md` (new) — was in old `index.md` |
| `buymeacoffe.png` | `docs/index.md` (new) — was in old `index.md` |
| `eth_address.png` | `docs/index.md` (new) — was in old `index.md` |

The Markdown references have been **left in place** so that re-uploading the
images will fix the rendering without any further change. The build emits a
warning for each one, but the warnings are **non-fatal** (`strict: false`).

### 4.2 Other issues

- **External link to a different repo**: `docs/red-team/host-privilege-escalation.md`
  points to `https://mvc1009.github.io/hackingnotes/privilege-escalation/windows-privesc/`,
  which is a *different* repository. Left as-is. If that repo is no longer
  reachable, the link will 404 in the rendered site.
- **Category typo**: The legacy front matter had `category: Maldev-LowPriv Evasaion`
  (typo). The new site uses the corrected name in the navigation
  ("Low Priv Evasion").
- **Unrecognized anchors** in `c2-cobaltstrike.md`: the text contains inline
  references like `[beacon_remote_exploit_register](https://...)` where the
  `https://...` part is itself a `#fragment`. MkDocs warns but does not abort.
  The links still work because the URLs are absolute.
- **Lone `*` syntax in the original index**: the old `index.md` used `*` for
  some bullets without a space. The new `index.md` was rewritten from scratch
  and uses standard Markdown.

## 5. Manual steps required on GitHub

After this branch is merged into `main`:

1. **Settings → Pages → Build and deployment → Source**: change to
   **GitHub Actions**. (The current setting is likely "Deploy from a branch"
   or was set up for CloudCannon.)
2. **Optional: disable CloudCannon** if the project was previously linked.
   CloudCannon keeps a webhook and may continue to push commits.
3. **Optional: enable GitHub Discussions / Issues** if desired for feedback.
4. **Confirm the workflow ran** under the **Actions** tab. The first deploy
   publishes the site at <https://benjugat.github.io/rtnotes/>.

## 6. Post-migration checklist

- [x] `mkdocs build` succeeds with exit code 0
- [x] Local `mkdocs serve` works
- [x] All 33 pages render
- [x] All 34 images copy to `site/images/`
- [x] Navigation matches the taxonomy in section 3.5
- [x] Search indexes every page
- [x] Light/dark palette toggles correctly
- [x] No 404s on internal links (within the migrated set)
- [x] `MIGRATION_TO_MKDOCS.md` documents everything
- [x] Workflow uses `actions/deploy-pages` and the official permissions
- [x] Legacy `_config.yml`, `Gemfile`, `_layouts/`, `_plugins/`, `_posts/`,
      `search.html`, `changelog.html`, `404.md`, `.cloudcannon/` removed

## 7. Future improvements

- **RSS / Atom feed**: add the `material[recommended]` plugins
  (`material/social`, `material/feed`) or `mkdocs-rss-plugin`.
- **Search analytics / lunr-languages**: enable stemming for Spanish
  (`es.json`) if the project is translated.
- **Versioning**: `mike` can publish multiple versions (e.g. `2026.06` and
  `main`) under `/rtnotes/2026.06/` and `/rtnotes/`.
- **Dark-mode first palette**: the current red accent + slate palette mirrors
  the original Jekyll theme. A future iteration could go red+black for full
  brand fidelity.
- **Re-add missing images**: drop the files listed in section 4.1 into
  `docs/images/`; the existing references will pick them up.
- **Redirect map for old URLs**: if the project ever gets indexed by Google
  under the old `/00-red-team/` URLs, install `mkdocs-redirects` and add
  mappings.
