"""Offline tests for bookmark-audit — no network, no real bookmarks echoed.

Run with:  python -m pytest tests/ -q
"""
import importlib.util
import os

import pytest

# --- load audit.py from the hyphenated module dir (can't `import bookmark-audit`)
_HERE = os.path.dirname(os.path.abspath(__file__))
_AUDIT_PATH = os.path.join(_HERE, "..", "audit.py")
_spec = importlib.util.spec_from_file_location("bookmark_audit_impl", _AUDIT_PATH)
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)

EXAMPLE_HTML = os.path.join(_HERE, "..", "examples", "sample_bookmarks.html")


# --------------------------------------------------------------------------
# Classification (pure)
# --------------------------------------------------------------------------
def test_classify_burner():
    assert audit.classify("https://temp-mail.org/", "Temp Mail") == \
        "Disposable Identity (burner email/SMS)"


def test_classify_router_default():
    assert audit.classify("https://routerpasswords.com/", "x") == \
        "Default Credentials / Router"


def test_classify_hash_cracker():
    assert audit.classify("https://crackstation.net/", "CrackStation") == \
        "Hash Cracking / Decryption"


def test_classify_wifi():
    assert audit.classify("https://github.com/JPaulMora/Pyrit", "Pyrit") == \
        "WiFi Audit / Cracking"


def test_classify_benign():
    assert audit.classify("https://www.apple.com/", "Apple") == \
        "Other / Uncategorized"


def test_classify_mozilla_vendor():
    assert audit.classify("https://support.mozilla.org/products/firefox", "Get Help") == \
        "Vendor / Help (browser default)"


def test_dual_use_flag():
    # burner is dual-use
    r = {"category": audit.classify("https://temp-mail.org/", "Temp Mail"),
         "url": "x"}
    # rebuild via classify path used in parse
    cat = audit.classify("https://temp-mail.org/", "Temp Mail")
    row = {"category": cat, "dual_use": cat in audit.DUAL_CATEGORIES}
    assert row["dual_use"] is True


def test_benign_not_dual_use():
    cat = audit.classify("https://www.apple.com/", "Apple")
    assert (cat in audit.DUAL_CATEGORIES) is False


# --------------------------------------------------------------------------
# HTML parsing
# --------------------------------------------------------------------------
def test_parse_html_counts():
    rows = audit.parse(EXAMPLE_HTML)
    assert len(rows) == 25


def test_parse_html_folders():
    rows = audit.parse(EXAMPLE_HTML)
    folders = {r["folder"] for r in rows}
    assert "Burner" in folders
    assert "PWs & Hashes / Credential Sites" in folders


def test_parse_html_skips_place():
    # No place: URIs in sample; just confirm structure
    rows = audit.parse(EXAMPLE_HTML)
    assert all(not r["url"].startswith("place:") for r in rows)


# --------------------------------------------------------------------------
# JSON parsing + dedupe (uses a synthetic Chromium JSON)
# --------------------------------------------------------------------------
def test_parse_chromium_json(tmp_path):
    data = {
        "roots": {
            "bookmark_bar": {
                "type": "folder", "name": "bookmark_bar",
                "children": [
                    {"type": "url", "name": "Apple", "url": "https://www.apple.com/"},
                    {"type": "url", "name": "Google", "url": "https://www.google.com/"},
                ],
            }
        },
        "version": 1,
    }
    p = tmp_path / "Bookmarks"
    p.write_text(__import__("json").dumps(data), encoding="utf-8")
    rows = audit.parse_chromium_json(str(p))
    assert len(rows) == 2
    assert rows[0]["folder"] == "bookmark_bar"
    assert rows[0]["category"] == "Other / Uncategorized"


def test_dedupe_json(tmp_path):
    data = {
        "roots": {
            "bookmark_bar": {
                "type": "folder", "name": "bookmark_bar",
                "children": [
                    {"type": "url", "name": "Apple", "url": "https://www.apple.com/"},
                    {"type": "url", "name": "Apple dup", "url": "https://www.apple.com/"},
                ],
            }
        },
        "version": 1,
    }
    p = tmp_path / "Bookmarks"
    p.write_text(__import__("json").dumps(data), encoding="utf-8")
    rows = audit.parse_chromium_json(str(p))
    assert len(rows) == 1  # deduped


def test_parse_auto_detects_json(tmp_path):
    data = {"roots": {"bookmark_bar": {"type": "folder", "name": "b",
            "children": [{"type": "url", "name": "X", "url": "https://x.com/"}]}},
            "version": 1}
    p = tmp_path / "Bookmarks"
    p.write_text(__import__("json").dumps(data), encoding="utf-8")
    rows = audit.parse_auto(str(p))
    assert len(rows) == 1


# --------------------------------------------------------------------------
# Clean / risk writers (offline)
# --------------------------------------------------------------------------
def test_write_clean_strips_icons(tmp_path):
    html = ('<A HREF="https://x.com/" ICON="data:image/png;base64,AAAA" '
            'ICON_URI="https://x.com/f.ico">X</A>')
    src = tmp_path / "in.html"
    src.write_text(html, encoding="utf-8")
    out = tmp_path / "clean.html"
    n = audit.write_clean(str(src), str(out))
    txt = out.read_text(encoding="utf-8")
    assert "ICON" not in txt
    assert "https://x.com/" in txt
    assert n > 0


def test_write_risk_split_routes_dual(tmp_path):
    html = ('<A HREF="https://temp-mail.org/" ADD_DATE="1">Temp Mail</A>\n'
            '<A HREF="https://www.apple.com/" ADD_DATE="1">Apple</A>')
    src = tmp_path / "in.html"
    src.write_text(html, encoding="utf-8")
    out = tmp_path / "risk.html"
    d = audit.write_risk_split(str(src), str(out))
    txt = out.read_text(encoding="utf-8")
    assert d == 1  # only the burner is dual-use
    assert "DUAL-USE" in txt
    assert "temp-mail.org" in txt


def test_build_json_shape():
    rows = audit.parse(EXAMPLE_HTML)
    j = audit.build_json(rows, "sample_bookmarks.html")
    assert j["total_links"] == 25
    assert j["dual_use_count"] == 23
    assert "links" in j and len(j["links"]) == 25
