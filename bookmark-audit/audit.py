#!/usr/bin/env python3
"""bookmark-audit — audit a browser bookmarks export for dual-use / risky links.

Part of the Ghostline cybersecurity suite (https://github.com/Mellowambience/ghostline).

*Invisible. Inevitable.*

Given a Netscape/Firefox bookmarks HTML export, this tool:
  1. parses every link + its folder path,
  2. classifies each link into a dual-use security category (or benign),
  3. emits a categorized inventory (markdown / csv / json),
  4. optionally writes a CLEAN export (icons stripped, tiny file),
  5. optionally writes a RISK-SPLIT export (dual-use links moved to a
     separate "authorized audit only" folder).

Possession of bookmarks is legal. The line is *whose* network/account you
point the tool at. This tool only helps you *see* your own collection.

Usage:
  python audit.py bookmarks.html --json
  python audit.py bookmarks.html --md report.md --csv report.csv
  python audit.py bookmarks.html --clean clean.html --risk risk.html

All CLI output supports --json for pipeline composability (Ghostline standard).
No third-party dependencies — standard library only.
"""
import sys
import re
import csv
import json
import html
import argparse
import os
from collections import OrderedDict

# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
TOKEN = re.compile(
    r'<H3[^>]*>(?P<h3>.*?)</H3>'
    r'|<A\s+(?P<aattrs>[^>]*)>(?P<atitle>.*?)</A>'
    r'|</DL\s*>',
    re.I | re.S,
)
ATTR = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
ENTITY = re.compile(r'&#(\d+);')


def clean(s: str) -> str:
    s = ENTITY.sub(lambda m: chr(int(m.group(1))), s)
    return html.unescape(s).strip()


# --------------------------------------------------------------------------
# Dual-use classification
# --------------------------------------------------------------------------
# Order matters: first match wins. Pattern is matched against "url + title" (lower).
CATEGORIES = OrderedDict([
    ("Disposable Identity (burner email/SMS)",
        [r'freesmsreceive', r'receive-sms', r'temp-mail', r'emailnator', r'10minutemail',
         r'guerrillamail', r'throwaway']),
    ("Default Credentials / Router",
        [r'routerpasswords', r'defaultpassword', r'open-sez', r'cirt\.net', r'default-password',
         r'defaultuserpass']),
    ("Hash Cracking / Decryption",
        [r'md5decrypt', r'crackstation', r'dcode\.fr', r'md5decrypter', r'hashtoolkit',
         r'weakpass', r'hashcat', r'john', r'decrypt']),
    ("WiFi Audit / Cracking",
        [r'pyrit', r'wepattack', r'cowpatty', r'airbase-ng', r'aircrack', r'fern-wifi',
         r'oswa', r'wifite', r'kali\.org/tools']),
    ("Password Recovery Tools",
        [r'nirsoft']),
    ("Hacking Resources / Blog",
        [r'anonhacktivism', r'hack', r'exploit', r'payload', r'secwiki', r'0day']),
    ("Vendor / Help (browser default)",
        [r'support\.mozilla', r'mozilla\.org']),
])


def classify(url: str, title: str) -> str:
    blob = (url + ' ' + title).lower()
    for cat, pats in CATEGORIES.items():
        if any(re.search(p, blob) for p in pats):
            return cat
    return "Other / Uncategorized"


DUAL_CATEGORIES = {k for k in CATEGORIES
                   if k not in ("Vendor / Help (browser default)",
                                "Other / Uncategorized")}


def parse(path: str):
    with open(path, encoding='utf-8', errors='replace') as f:
        data = f.read()
    stack = []
    rows = []
    for m in TOKEN.finditer(data):
        if m.group('h3') is not None:
            stack.append(clean(m.group('h3')))
        elif m.group(0).startswith('</DL'):
            if stack:
                stack.pop()
        elif m.group('aattrs') is not None:
            attrs = dict(ATTR.findall(m.group('aattrs')))
            url = attrs.get('HREF', '').strip()
            if not url or url.startswith('place:'):
                continue
            title = clean(m.group('atitle'))
            folder = (' / '.join(stack[1:]) if len(stack) > 1
                      else (stack[0] if stack else '(root)'))
            cat = classify(url, title)
            rows.append({
                'folder': folder,
                'title': title,
                'url': url,
                'add_date': attrs.get('ADD_DATE', ''),
                'last_modified': attrs.get('LAST_MODIFIED', ''),
                'category': cat,
                'dual_use': cat in DUAL_CATEGORIES,
            })
    return rows


# --------------------------------------------------------------------------
# Chromium JSON bookmarks (Chrome / Edge / Opera / Brave) importer
# --------------------------------------------------------------------------
def parse_chromium_json(path: str):
    with open(path, encoding='utf-8', errors='replace') as f:
        data = json.load(f)

    rows = []

    def walk(node, path):
        t = node.get('type')
        name = node.get('name', '')
        if t == 'url':
            url = node.get('url', '').strip()
            if not url or url.startswith('place:'):
                return
            folder = (' / '.join(path[1:]) if len(path) > 1
                      else (path[0] if path else '(root)'))
            cat = classify(url, name)
            rows.append({
                'folder': folder,
                'title': name,
                'url': url,
                'add_date': str(node.get('date_added', '')),
                'last_modified': str(node.get('date_modified', '')),
                'category': cat,
                'dual_use': cat in DUAL_CATEGORIES,
            })
        elif t == 'folder':
            for child in node.get('children', []):
                walk(child, path + [name])

    for root_key, root_node in data.get('roots', {}).items():
        walk(root_node, [root_key])

    # Deduplicate by URL (Opera/Chromium exports can contain duplicate
    # bookmark-bar entries). Keep the first folder path encountered.
    seen, deduped = set(), []
    for r in rows:
        if r['url'] in seen:
            continue
        seen.add(r['url'])
        deduped.append(r)
    return deduped


def parse_auto(path: str):
    """Detect format: Chromium JSON vs Netscape HTML."""
    with open(path, encoding='utf-8', errors='replace') as f:
        head = f.read(4096)
    if head.lstrip().startswith('{') or '"roots"' in head:
        return parse_chromium_json(path)
    return parse(path)


# --------------------------------------------------------------------------
# Output builders
# --------------------------------------------------------------------------
def build_markdown(rows, src_name):
    by_cat = OrderedDict()
    for r in rows:
        by_cat.setdefault(r['category'], []).append(r)
    by_folder = OrderedDict()
    for r in rows:
        by_folder.setdefault(r['folder'], []).append(r)

    L = [f"# Bookmark Audit — {src_name}", ""]
    L.append(f"**Total links:** {len(rows)}")
    L.append(f"**Dual-use (review):** {sum(1 for r in rows if r['dual_use'])}")
    L.append("")
    L.append("## By category")
    L.append("")
    for cat, items in sorted(by_cat.items(), key=lambda kv: -len(kv[1])):
        L.append(f"- **{cat}**: {len(items)}")
    L.append("")
    L.append("## Full list (grouped by folder path)")
    L.append("")
    for folder, items in by_folder.items():
        L.append(f"### {folder}")
        L.append("")
        for r in items:
            tag = "dual-use" if r['dual_use'] else "benign"
            L.append(f"- [{r['title']}]({r['url']})  _{tag} · {r['category']}_")
        L.append("")
    return "\n".join(L)


def build_json(rows, src_name):
    by_cat = OrderedDict()
    for r in rows:
        by_cat.setdefault(r['category'], []).append(r['url'])
    return {
        'source': src_name,
        'total_links': len(rows),
        'dual_use_count': sum(1 for r in rows if r['dual_use']),
        'categories': {k: len(v) for k, v in by_cat.items()},
        'links': rows,
    }


# --------------------------------------------------------------------------
# HTML writers
# --------------------------------------------------------------------------
def write_clean(src_path, out_path):
    with open(src_path, encoding='utf-8', errors='replace') as f:
        raw = f.read()
    clean = re.sub(r'\s+ICON_URI="[^"]*"', '', raw)
    clean = re.sub(r'\s+ICON="[^"]*"', '', clean)
    clean = re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*?></meta>', '', clean, flags=re.I)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(clean)
    return len(clean)


def write_risk_split(src_path, out_path):
    with open(src_path, encoding='utf-8', errors='replace') as f:
        raw = f.read()
    dual = []
    seen = set()
    for m in re.finditer(r'<A\s+([^>]*)>(.*?)</A>', raw, re.I | re.S):
        attrs = m.group(1)
        title = html.unescape(m.group(2)).strip()
        href = re.search(r'HREF="([^"]*)"', attrs)
        if not href:
            continue
        url = href.group(1)
        if url in seen:
            continue
        if classify(url, title) in DUAL_CATEGORIES and url not in seen:
            seen.add(url)
            dual.append(f'        <DT><A HREF="{url}" ADD_DATE="0">{title}</A>')
    # clean icons from the rest
    rest = re.sub(r'\s+ICON_URI="[^"]*"', '', raw)
    rest = re.sub(r'\s+ICON="[^"]*"', '', rest)
    block = ""
    if dual:
        block = ('    <DT><H3>DUAL-USE (authorized audit only)</H3>\n'
                 '    <DL><p>\n' + "\n".join(dual) + '\n    </DL><p>\n')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('<!DOCTYPE NETSCAPE-Bookmark-file-1>\n')
        f.write('<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">\n')
        f.write('<TITLE>Bookmarks (risk-split)</TITLE>\n<H1>Bookmarks Menu</H1>\n\n<DL><p>\n')
        f.write(block)
        idx = rest.find('<DL><p>')
        f.write(rest[idx:] if idx != -1 else rest)
        f.write('\n</DL><p>\n')
    return len(dual)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Audit a browser bookmarks export for dual-use / risky links.")
    ap.add_argument('bookmarks', help="path to bookmarks HTML export")
    ap.add_argument('--json', action='store_true', help="print JSON to stdout")
    ap.add_argument('--md', metavar='OUT.md', help="write markdown report")
    ap.add_argument('--csv', metavar='OUT.csv', help="write CSV of all links")
    ap.add_argument('--clean', metavar='OUT.html', help="write icon-stripped clean export")
    ap.add_argument('--risk', metavar='OUT.html', help="write risk-split export")
    args = ap.parse_args()

    if not os.path.exists(args.bookmarks):
        sys.exit(f"error: file not found: {args.bookmarks}")

    rows = parse_auto(args.bookmarks)
    src = os.path.basename(args.bookmarks)

    if args.csv:
        with open(args.csv, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(
                f, fieldnames=['folder', 'title', 'url', 'add_date',
                               'last_modified', 'category', 'dual_use'])
            w.writeheader()
            w.writerows(rows)
        print(f"[written] {args.csv}")

    if args.clean:
        n = write_clean(args.bookmarks, args.clean)
        print(f"[written] {args.clean} ({n // 1024} KB)")

    if args.risk:
        d = write_risk_split(args.bookmarks, args.risk)
        print(f"[written] {args.risk} ({d} dual-use links routed to a separate folder)")

    if args.json:
        print(json.dumps(build_json(rows, src), indent=2))
    elif args.md:
        with open(args.md, 'w', encoding='utf-8') as f:
            f.write(build_markdown(rows, src))
        print(f"[written] {args.md}")
    elif not (args.csv or args.clean or args.risk):
        # default: human-readable report to stdout
        print(build_markdown(rows, src))


if __name__ == '__main__':
    main()
