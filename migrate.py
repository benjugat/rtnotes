"""
MkDocs migration script for benjugat/rtnotes (v3 - friendly cross-ref labels).
Pass 1: copy and transform front matter, fix images.
Pass 2: rewrite cross-references now that all files exist, with friendly labels.
Pass 3: clean up nested brackets.
"""
import os
import re
from pathlib import Path

ROOT = Path(".").resolve()
SRC = ROOT / "_docs"
DST = ROOT / "docs"

DIR_MAP = {
    "00-red-team": "red-team",
    "malware": "malware",
    "user-impersonation": "red-team",
}

SITE_BASE = "https://benjugat.github.io/rtnotes"

IMG_PATTERNS = [
    re.compile(r"\(/rtnotes/images/([^)]+)\)"),
    re.compile(r"\(/hackingnotes/images/([^)]+)\)"),
    re.compile(r"\(/images/([^)]+)\)"),
]

def parse_front_matter(text):
    if not text.startswith("---"):
        return ({}, text)
    end = text.find("\n---", 3)
    if end == -1:
        return ({}, text)
    fm_block = text[3:end].strip()
    body = text[end+4:].lstrip("\n")
    fm = {}
    for line in fm_block.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fm[k.strip()] = v.strip()
    return (fm, body)

def make_description(body, title):
    for line in body.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith(("#", ">", "!", "|", "```", "-", "*", "---")):
            continue
        s = re.sub(r"^[\*_`]+|[\*_`]+$", "", s).strip()
        if len(s) > 160:
            s = s[:157].rsplit(" ", 1)[0] + "..."
        return s.replace('"', "'")
    return title

def transform_images(body, current_dest_path):
    for pat in IMG_PATTERNS:
        def img_repl(m):
            fname = m.group(1)
            img_target = (DST / "images" / fname).resolve()
            try:
                rel = os.path.relpath(img_target, start=current_dest_path.parent).replace("\\", "/")
                return f"({rel})"
            except Exception:
                return f"(images/{fname})"
        body = pat.sub(img_repl, body)
    return body

def all_md_files():
    return sorted(DST.rglob("*.md"))

def get_title_for(md_path: Path) -> str:
    try:
        text = md_path.read_text(encoding="utf-8")
    except Exception:
        return md_path.stem.replace("-", " ").title()
    fm, _ = parse_front_matter(text)
    return fm.get("title", md_path.stem.replace("-", " ").title())

def find_md_for_url_suffix(suffix):
    suffix = suffix.strip("/")
    if not suffix:
        return None
    exact = DST / (suffix + ".md")
    if exact.exists():
        return exact
    base = DST / suffix
    if base.exists() and base.is_dir():
        idx = base / "index.md"
        if idx.exists():
            return idx
    return None

def rewrite_xrefs_pass():
    """Pass 2: convert cross-references to relative .md paths with friendly labels."""
    site_re = re.compile(re.escape(SITE_BASE) + r"/([A-Za-z0-9_\-./]+)/?")
    fixed = 0
    skipped = 0
    for md in all_md_files():
        text = md.read_text(encoding="utf-8")
        original = text
        def repl(m):
            nonlocal fixed, skipped
            suffix = m.group(1)
            target = find_md_for_url_suffix(suffix)
            if target is None:
                skipped += 1
                return m.group(0)
            rel = os.path.relpath(target, start=md.parent).replace("\\", "/")
            fixed += 1
            return f"({rel})"
        text = site_re.sub(repl, text)
        if text != original:
            md.write_text(text, encoding="utf-8")
    # Cleanup pass 3: collapse [(text)]((target)) patterns.
    nested_re = re.compile(r"\[\(([^)\n]+)\)\]\(\(([^)\n]+)\)\)")
    cleaned = 0
    for md in all_md_files():
        text = md.read_text(encoding="utf-8")
        def friendlify(m):
            nonlocal cleaned
            link_text = m.group(1)
            link_target = m.group(2)
            # If the target ends with .md, try to friendlify the label
            if link_target.endswith(".md"):
                target_path = (md.parent / link_target).resolve()
                # Try to find the actual file (resolve .. etc.)
                try:
                    rel = os.path.relpath(target_path, DST).replace("\\", "/")
                    actual = DST / rel
                    if actual.exists():
                        friendly = get_title_for(actual)
                        cleaned += 1
                        return f"[{friendly}]({link_target})"
                except Exception:
                    pass
            cleaned += 1
            return f"[{link_text}]({link_target})"
        new_text, _ = nested_re.subn(friendlify, text)
        if new_text != text:
            md.write_text(new_text, encoding="utf-8")
    print(f"Cross-refs rewritten: {fixed} fixed, {skipped} unresolved; nested-link cleanups: {cleaned}.")

def migrate():
    # Ensure images are copied
    img_src = ROOT / "images"
    img_dst = DST / "images"
    img_dst.mkdir(parents=True, exist_ok=True)
    if img_src.exists():
        for f in img_src.iterdir():
            if f.is_file():
                (img_dst / f.name).write_bytes(f.read_bytes())

    summary = []
    for src_file in sorted(SRC.rglob("*.md")):
        if src_file.name == "_defaults.md":
            continue
        rel = src_file.relative_to(SRC)
        parts = rel.parts
        top = parts[0]
        if top not in DIR_MAP:
            summary.append((str(rel), "SKIP"))
            continue
        dest_dir = DST / DIR_MAP[top]
        if len(parts) == 1:
            dest_path = dest_dir / src_file.name
        else:
            sub_parts = parts[1:]
            dest_path = dest_dir.joinpath(*sub_parts)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        text = src_file.read_text(encoding="utf-8")
        fm, body = parse_front_matter(text)
        title = fm.get("title", src_file.stem.replace("-", " ").title())
        desc = make_description(body, title)
        new_fm = f'---\ntitle: {title}\ndescription: "{desc}"\n---\n'
        body = transform_images(body, dest_path)
        if not body.startswith("\n"):
            body = "\n" + body
        dest_path.write_text(new_fm + body, encoding="utf-8")
        summary.append((str(rel), "OK", str(dest_path.relative_to(ROOT))))

    print("Pass 1 done:")
    for s in summary:
        print(f"  {s[0]:60s} -> {s[1]:6s} {s[2] or ''}")
    print()
    rewrite_xrefs_pass()

if __name__ == "__main__":
    migrate()
