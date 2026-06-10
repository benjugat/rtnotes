---
title: Red Team Notes
description: Red teaming and malware development notes for offensive security operators.
---

# Red Team Notes

A field notebook for offensive security operators. These notes collect tactics,
techniques, and procedures (TTPs) encountered during red team engagements and
malware development research. The goal is to have a single, fast-searchable
reference you can use during an assessment.

> **Disclaimer:** The material here is for educational and authorized testing
> only. Use it only on systems you own or have explicit permission to test.

## Where to start

<div class="grid cards" markdown>

-   :material-shield-half-full:{ .lg .middle } **Red Team**

    ---

    End-to-end offensive operations: OPSEC, C2, host recon, persistence,
    privilege escalation, lateral movement, exfiltration, and AD internals.

    [:octicons-arrow-right-24: Start with the Introduction](red-team/introduction.md)

-   :material-bug:{ .lg .middle } **Malware Development**

    ---

    Windows internals and offensive engineering: code injection, hooking,
    evasion, and object enumeration, with annotated C/C++ snippets.

    [:octicons-arrow-right-24: Jump to Code Injection](malware/code-injection/intro.md)

-   :material-magnify:{ .lg .middle } **Full-text search**

    ---

    Press <kbd>/</kbd> or click the search icon in the top bar to search every
    page. Material for MkDocs indexes headings, code blocks and tables.

-   :material-github:{ .lg .middle } **Source on GitHub**

    ---

    The site is generated from Markdown in `docs/`. Edit any page and open a
    pull request.

    [:octicons-arrow-right-24: benjugat/rtnotes](https://github.com/benjugat/rtnotes)

</div>

## Project layout

```
docs/
├── index.md                # This page
├── changelog.md            # Build / content changelog
├── red-team/               # Operations, C2, AD, lateral movement, etc.
│   ├── introduction.md
│   ├── opsec-infrastructure.md
│   ├── c2-cobaltstrike.md
│   └── ...
├── malware/                # Windows internals & offensive engineering
│   ├── basics/
│   ├── code-injection/
│   ├── hooking/
│   ├── lowpriv-evasion/
│   └── object-enumeration/
└── images/                 # All static assets
```

## Conventions used in the notes

- Code samples are usually C/C++ unless otherwise stated.
- Beacon examples assume Cobalt Strike; the same patterns apply to other C2s.
- OPSEC notes are flagged with `!!! note "OPSEC"` admonitions.
- Use the left sidebar to navigate by section. Use the right sidebar (or
  <kbd>/</kbd>) to search.
