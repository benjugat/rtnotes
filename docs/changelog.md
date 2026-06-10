---
title: Changelog
description: Content and infrastructure changes to the Red Team Notes site.
---

# Changelog

This page tracks notable changes to the **content** and the **infrastructure**
of the Red Team Notes site. For the full commit history see the
[GitHub repository](https://github.com/benjugat/rtnotes/commits/main).

## 2026-06-10 — MkDocs migration

The site was migrated from Jekyll (CloudCannon Edition template) to
**MkDocs with Material for MkDocs**.

Highlights:

- New navigation: two top-level sections (**Red Team**, **Malware Development**)
  with sub-sections grouped by topic.
- Native full-text search powered by Material.
- Bilingual palette (light / dark) with the project's red accent.
- Automated deployment via GitHub Actions (`actions/deploy-pages`) on every
  push to `main`.
- Markdown front matter simplified to `title` + `description`.
- Old URLs (`/00-red-team/...`) replaced with `/red-team/...`. External links
  to the legacy site (e.g. from bookmarks) will need to be updated.

See [`MIGRATION_TO_MKDOCS.md`](https://github.com/benjugat/rtnotes/blob/main/MIGRATION_TO_MKDOCS.md)
on GitHub for the full migration report.

## Earlier history

The repository was previously built with **Jekyll 3.8.4** on CloudCannon,
using the *Edition* template (jekyll-feed, jekyll-seo-tag, jekyll-sitemap).
The legacy changelog at `changelog.html` was scaffolded by the template and
is no longer served.
