"""Tests for the ghostline profile/report/doctor layer (offline, no network)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghostline_profiles import list_profiles, load_profile, render_markdown


def test_list_profiles_finds_yaml():
    names = list_profiles()
    assert "home-audit" in names
    assert "account-hygiene" in names
    assert "pre-travel" in names


def test_load_profile_home_audit():
    spec = load_profile("home-audit")
    assert spec["title"] == "Home Audit"
    assert any(s["module"] == "vault" for s in spec["steps"])


def test_render_markdown_has_profile_title():
    fake = {
        "profile": "home-audit",
        "title": "Home Audit",
        "ran_at": "2026-07-20T00:00:00+00:00",
        "ok": True,
        "steps": [
            {"module": "dns", "ok": True, "error": None, "data": {"raw": "cf 1.1.1.1"}},
        ],
    }
    md = render_markdown(fake)
    assert "# Ghostline report: Home Audit" in md
    assert "Status: OK" in md
    assert "## dns" in md
