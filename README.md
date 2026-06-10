# Red Team Notes

Personal field notebook for **offensive security operators**: red team
operations, C2 tradecraft, Windows internals, malware development, and
Active Directory abuse.

The site is built with **[MkDocs](https://www.mkdocs.org/)** using
**[Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)** and is
automatically deployed to **GitHub Pages** on every push to `main`.

> Live site: <https://benjugat.github.io/rtnotes/>

## Stack

- **Generator**: MkDocs 1.6+
- **Theme**: Material for MkDocs 9.5+
- **Markdown extensions**: admonition, superfences, tabbed, highlight,
  inlinehilite, snippets, tasklist, emoji, details, attr_list, def_list, tables
- **Deploy**: GitHub Actions → `actions/deploy-pages` (no `gh-pages` branch)
- **Search**: Native (lunr via Material)

## Local development

### 1. Install Python

Any Python ≥ 3.9 is fine.

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Serve the site locally

```bash
python -m mkdocs serve
```

Open <http://127.0.0.1:8000/rtnotes/> in your browser. The dev server
auto-reloads on every change to `docs/` or `mkdocs.yml`.

> The trailing `/rtnotes/` is required because the site is served under
> `/<repo>/` on GitHub Pages. Material honours `site_url` to compute correct
> asset paths in local dev.

### 4. Build a static site

```bash
python -m mkdocs build
```

Output goes to `site/` (gitignored). The contents of `site/` are exactly what
GitHub Pages will serve.

## Project layout

```
.
├── .github/workflows/ci.yml     # GitHub Pages deploy
├── docs/                        # All Markdown content
│   ├── index.md                 # Home page
│   ├── changelog.md             # This changelog (rendered)
│   ├── red-team/                # Red Team section
│   ├── malware/                 # Malware Development section
│   │   ├── basics/
│   │   ├── code-injection/
│   │   ├── hooking/
│   │   ├── lowpriv-evasion/
│   │   └── object-enumeration/
│   └── images/                  # All static assets
├── mkdocs.yml                   # MkDocs configuration
├── requirements.txt             # Python dependencies
├── MIGRATION_TO_MKDOCS.md       # Migration report (Jekyll → MkDocs)
├── robots.txt
├── LICENSE
└── README.md
```

## Adding a new page

1. Create a new `.md` file under the appropriate section, e.g.
   `docs/red-team/new-topic.md`.
2. Add a `title` and short `description` in the front matter:

   ```markdown
   ---
   title: New Topic
   description: One-liner that shows up in search and meta tags.
   ---

   # New Topic

   Content here.
   ```

3. Register the page in the `nav:` block of `mkdocs.yml` so it appears in the
   sidebar.
4. Reference images as relative paths, e.g. `../images/foo.png` from
   `docs/red-team/whatever.md`, or `images/foo.png` from `docs/index.md`.

## Deploying

Pushing to `main` triggers `.github/workflows/ci.yml`, which:

1. Installs the dependencies.
2. Runs `mkdocs build` to produce `site/`.
3. Uploads `site/` as a Pages artifact.
4. Deploys it to GitHub Pages.

> **One-time setup**: In the repository settings, go to
> **Pages → Build and deployment → Source** and select **GitHub Actions**.
> If it was previously set to "Deploy from a branch" or to CloudCannon,
> change it to GitHub Actions to start receiving the workflow output.

## License

MIT — see [`LICENSE`](LICENSE).
