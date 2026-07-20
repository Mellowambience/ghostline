"""ghostline_profiles.py -- the composed-workflow layer (Path A orchestration).

Reads profiles/*.yaml, runs each step's module with --json, merges results into
one report (Markdown + HTML), and stores run history under ~/.ghostline/reports/.

This is what turns "7 tools in a folder" into "Ghostline".
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

import yaml

PROFILES_DIR = os.path.join(os.path.dirname(__file__), "profiles")
REPORTS_DIR = os.path.expanduser("~/.ghostline/reports")

# module subcommand -> executable (mirrors ghostline_cli.MODULES)
MODULE_EXE = {
    "scan": "ghost-scan",
    "vault": "vaultcheck",
    "dns": "ghostdns",
    "trace": "phantomtrace",
    "audit": "shadowaudit",
    "account": "accountwatch",
    "bookmarks": "bookmark-audit",
}


def list_profiles() -> list[str]:
    if not os.path.isdir(PROFILES_DIR):
        return []
    return sorted(
        p[:-5] for p in os.listdir(PROFILES_DIR)
        if p.endswith(".yaml") or p.endswith(".yml")
    )


def load_profile(name: str) -> dict:
    for ext in (".yaml", ".yml"):
        path = os.path.join(PROFILES_DIR, name + ext)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                return yaml.safe_load(f)
    raise FileNotFoundError(f"profile '{name}' not found in {PROFILES_DIR}")


def run_step(step: dict) -> dict:
    """Run one profile step. Returns a structured result dict.

    `step['args']` are passed VERBATIM to the module executable — the profile
    author is responsible for placing `--json` where the module supports it
    (modules differ: bookmark-audit takes top-level --json; vaultcheck/shadowaudit
    are Click groups needing `check --json` / `scan --json`; ghostdns has no
    JSON mode yet and degrades to raw text).
    """
    mod = step["module"]
    exe = MODULE_EXE.get(mod, mod)
    if shutil.which(exe) is None:
        return {"module": mod, "ok": False, "error": f"{exe} not installed",
                "data": None}
    args = list(step.get("args", []))
    try:
        proc = subprocess.run([exe, *args], capture_output=True, text=True,
                              timeout=step.get("timeout", 60))
    except subprocess.TimeoutExpired:
        return {"module": mod, "ok": False, "error": "timeout", "data": None}
    raw = (proc.stdout or proc.stderr).strip()
    data = None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = {"raw": raw[:2000]}  # degrade: keep text
    return {"module": mod, "ok": proc.returncode == 0 and bool(data),
            "error": None, "data": data}


def run_profile(name: str) -> dict:
    spec = load_profile(name)
    steps = spec.get("steps", [])
    results = [run_step(s) for s in steps]
    ts = datetime.now(timezone.utc)
    report = {
        "profile": name,
        "title": spec.get("title", name),
        "ran_at": ts.isoformat(),
        "steps": results,
        "ok": all(r["ok"] for r in results),
    }
    _store(report)
    return report


def _store(report: dict):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    fname = f"{report['profile']}_{report['ran_at'][:19].replace(':','-')}.json"
    with open(os.path.join(REPORTS_DIR, fname), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def render_markdown(report: dict) -> str:
    lines = [f"# Ghostline report: {report['title']}",
             f"- Ran: {report['ran_at']}",
             f"- Status: {'OK' if report['ok'] else 'DEGRADED'}", ""]
    for r in report["steps"]:
        lines.append(f"## {r['module']} — {'ok' if r['ok'] else 'FAILED'}")
        if r["error"]:
            lines.append(f"  error: {r['error']}")
        elif r["data"]:
            lines.append("```json")
            lines.append(json.dumps(r["data"], indent=2)[:1500])
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


def render_html(report: dict) -> str:
    body = render_markdown(report).replace("\n", "<br>")
    return f"<html><head><title>Ghostline {report['profile']}</title></head><body>{body}</body></html>"


def list_reports(days: int = 30) -> list[dict]:
    if not os.path.isdir(REPORTS_DIR):
        return []
    out = []
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    for f in sorted(os.listdir(REPORTS_DIR)):
        if not f.endswith(".json"):
            continue
        p = os.path.join(REPORTS_DIR, f)
        try:
            with open(p, encoding="utf-8") as fh:
                r = json.load(fh)
            if datetime.fromisoformat(r["ran_at"]).timestamp() >= cutoff:
                out.append(r)
        except Exception:
            continue
    return out


if __name__ == "__main__":
    # quick self-test
    print("profiles:", list_profiles())
